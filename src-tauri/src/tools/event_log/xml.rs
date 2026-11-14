//! Exported Windows event XML (Event Viewer "Save as XML", `wevtutil qe
//! /f:xml`, `Get-WinEvent | ... ToXml()`). Each `<Event>` is converted into
//! the JSON shape the `evtx` crate produces, so one normalizer handles both.
//! DTDs and entity declarations are ignored, never resolved; only the five
//! predefined entities and character references are expanded.

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use serde_json::{Map, Value};

use super::model::{self, EventRecord};

/// Deepest element nesting accepted.
const MAX_DEPTH: usize = 64;

#[derive(Default)]
struct Node {
    name: String,
    attrs: Vec<(String, String)>,
    text: String,
    children: Vec<Node>,
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

fn predefined(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => None,
    }
}

/// Convert a node into the evtx JSON shape.
fn to_value(n: &Node) -> Value {
    let text = n.text.trim();
    if n.children.is_empty() && n.attrs.is_empty() {
        return Value::String(text.to_string());
    }
    let mut o = Map::new();
    if !n.attrs.is_empty() {
        let attrs: Map<String, Value> = n
            .attrs
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        o.insert("#attributes".into(), Value::Object(attrs));
    }
    if n.name == "EventData" {
        // <Data Name="X">v</Data> becomes "X": "v"; unnamed Data stays a list.
        let mut unnamed = Vec::new();
        for c in &n.children {
            match c.attrs.iter().find(|(k, _)| k == "Name") {
                Some((_, name)) => {
                    o.insert(name.clone(), Value::String(c.text.trim().to_string()));
                }
                None => unnamed.push(to_value(c)),
            }
        }
        if !unnamed.is_empty() {
            o.insert("Data".into(), Value::Array(unnamed));
        }
    } else {
        for c in &n.children {
            let v = to_value(c);
            match o.get_mut(&c.name) {
                Some(Value::Array(a)) => a.push(v),
                Some(existing) => {
                    let first = existing.take();
                    *existing = Value::Array(vec![first, v]);
                }
                None => {
                    o.insert(c.name.clone(), v);
                }
            }
        }
    }
    if !text.is_empty() {
        o.insert("#text".into(), Value::String(text.to_string()));
    }
    Value::Object(o)
}

/// Result of an XML import: records plus problems found along the way.
pub struct XmlImport {
    pub records: Vec<EventRecord>,
    pub errors: Vec<String>,
    pub truncated: bool,
}

/// Parse every `<Event>` in `text`, up to `max` records.
pub fn parse(text: &str, max: usize) -> XmlImport {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<Node> = Vec::new();
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut truncated = false;

    loop {
        let ev = match reader.read_event() {
            Ok(ev) => ev,
            Err(e) => {
                errors.push(format!(
                    "XML error at byte {}: {e}",
                    reader.error_position()
                ));
                break;
            }
        };
        match ev {
            Event::Start(e) => {
                let name = local(e.name().as_ref());
                if stack.is_empty() && name != "Event" {
                    continue; // <Events> wrapper or other outer elements
                }
                if stack.len() >= MAX_DEPTH {
                    errors.push("XML nested too deeply; stopped".into());
                    break;
                }
                let attrs = e
                    .attributes()
                    .flatten()
                    .map(|a| {
                        (
                            local(a.key.as_ref()),
                            a.normalized_value(XmlVersion::Implicit1_0)
                                .map(|v| v.into_owned())
                                .unwrap_or_default(),
                        )
                    })
                    .collect();
                stack.push(Node {
                    name,
                    attrs,
                    ..Default::default()
                });
            }
            Event::Empty(e) => {
                if stack.is_empty() {
                    continue;
                }
                let attrs = e
                    .attributes()
                    .flatten()
                    .map(|a| {
                        (
                            local(a.key.as_ref()),
                            a.normalized_value(XmlVersion::Implicit1_0)
                                .map(|v| v.into_owned())
                                .unwrap_or_default(),
                        )
                    })
                    .collect();
                let node = Node {
                    name: local(e.name().as_ref()),
                    attrs,
                    ..Default::default()
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                }
            }
            Event::Text(t) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&t.xml10_content());
                }
            }
            Event::CData(c) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&c);
                }
            }
            Event::GeneralRef(r) => {
                if let Some(top) = stack.last_mut() {
                    if let Ok(Some(c)) = r.resolve_char_ref() {
                        top.text.push(c);
                    } else if let Some(c) = predefined(&r.xml10_content()) {
                        top.text.push(c);
                    }
                    // Any other entity is dropped: no DTD expansion.
                }
            }
            Event::End(_) => {
                let Some(node) = stack.pop() else { continue };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    if records.len() >= max {
                        truncated = true;
                        break;
                    }
                    let value =
                        Value::Object(Map::from_iter([("Event".to_string(), to_value(&node))]));
                    records.push(model::from_event_json(
                        records.len() as u32,
                        &value,
                        None,
                        "",
                    ));
                }
            }
            Event::Eof => break,
            _ => {} // DocType, PI, Decl, Comment: ignored
        }
    }
    if !stack.is_empty() && errors.is_empty() {
        errors.push(
            "the file ended inside an <Event>; the last record is incomplete and was skipped"
                .into(),
        );
    }
    XmlImport {
        records,
        errors,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4624</EventID>
    <Level>0</Level>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-13T14:05:10.5000000Z"/>
    <EventRecordID>77</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WS01.corp.example</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice &amp; co &#x41;&xxe;</Data>
    <Data Name="LogonType">10</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager" EventSourceName="Service Control Manager"/>
    <EventID Qualifiers="16384">7045</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-11-13T14:06:00.000Z"/>
    <Channel>System</Channel>
    <Computer>WS01</Computer>
  </System>
  <EventData><Data>svc</Data><Data>C:\x.exe</Data></EventData>
</Event>
</Events>"#;

    #[test]
    fn parses_exported_events() {
        let imp = parse(SAMPLE, 100);
        assert!(imp.errors.is_empty(), "{:?}", imp.errors);
        assert_eq!(imp.records.len(), 2);
        let a = &imp.records[0];
        assert_eq!(a.event_id, 4624);
        assert_eq!(a.outcome, "Audit Success");
        assert_eq!(a.record_id, Some(77));
        assert_eq!(a.time_utc_ms, Some(1_794_578_710_500));
        // Predefined and character references expand; the external entity does not.
        assert_eq!(a.field("TargetUserName"), Some("alice & co A"));
        let b = &imp.records[1];
        assert_eq!(b.event_id, 7045);
        assert_eq!(b.provider, "Service Control Manager");
        assert_eq!(
            b.fields,
            vec![
                ("Data[0]".to_string(), "svc".to_string()),
                ("Data[1]".to_string(), "C:\\x.exe".to_string())
            ]
        );
        assert_eq!(b.index, 1);
    }

    #[test]
    fn limits_and_damage() {
        let imp = parse(SAMPLE, 1);
        assert_eq!(imp.records.len(), 1);
        assert!(imp.truncated);
        let cut = &SAMPLE[..SAMPLE.find("<EventData>").unwrap()];
        let imp = parse(cut, 100);
        assert_eq!(imp.records.len(), 0);
        assert_eq!(imp.errors.len(), 1);
        let deep = format!("<Event>{}</Event>", "<a>".repeat(200));
        assert!(parse(&deep, 10).errors.iter().any(|e| e.contains("deeply")));
        assert!(parse("not xml at all <<<", 10).records.is_empty());
    }
}
