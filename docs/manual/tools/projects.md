# Projects

> Collect results from several tools into one named project, order and annotate them, and export the whole set as one report.

**Sidebar group:** Workspace · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Build one deliverable for a troubleshooting session or assessment: DNS audit, TLS check, port scan and traceroute in a single HTML or PDF.
- Keep the evidence for a ticket or change together, with a scope note and ticket number at the top.
- Hand a redacted report to a vendor or another team without exposing internal names and addresses.
- Collect timestamped notes about each tool's work alongside the saved results.

## Quick start

1. Open **Projects** (top of the sidebar, under Workspace).
2. Type a name in **New project name** and press Enter or click **Create**.
3. Fill in **Notes** with scope, ticket number or similar. It is printed in the report overview.
4. Go to any tool, run it, then open its **Export** menu and pick the project under **Add to project**. **New project...** creates one and adds the result in one step.
5. After adding, click **Open** next to the confirmation message to jump back to the project.
6. In Projects, reorder results with the arrows, rename them, add a note to each, and remove any you do not need.
7. Under **Export all**, click HTML, PDF, Markdown or Plain text, or **Redacted...**, and choose where to save.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| New project name / Create | Creates a project and selects it. | Up to 200 characters. An empty name becomes "Untitled project". |
| Project list | All projects, most recently updated first, with result count and last update time. Click one to select it. | The first project, or the one opened from an Export menu, is selected on open. |
| Name | Renames the selected project. | Up to 200 characters. |
| Notes | Free text for the whole project, printed in the report's Overview section. | Up to 20,000 characters. |
| Export all: HTML, PDF, Markdown, Plain text | Exports every result and note in the project as one file. | Disabled when the project has no results and no notes. |
| Redacted... | Exports the whole project through the redaction dialog. See [Export and redaction](../export-and-redaction.md). | Disabled when the project has no results. |
| Use for notes / Active for notes | Makes this project the target for the notes pop-out. See [Projects and notes](../projects-and-notes.md). | |
| Delete project | Deletes the project and all its saved results after confirmation. Cannot be undone. | |
| Result title | Editable title of each saved result. | Up to 200 characters. Clearing it restores the original report title. |
| Up / down arrows | Change the order results appear in the export. | |
| x (Remove) | Removes one result after confirmation. | |
| Note for this result | Optional note printed with that result in the export. | Up to 20,000 characters. |

Edits to names, titles and notes save automatically about half a second after you stop typing, and when the field loses focus. Reordering and removing save at once. "Last saved" at the bottom shows the time of the last save.

### Adding results from tools

Every tool with an **Export** menu has an **Add to project** section. It lists the six most recently updated projects with their result counts, plus **New project...** (type a name, then Enter or **Add**). The message "Added to NAME (N results)" confirms it, with an **Open** link. Tools without an Export menu, such as [Regex Builder](regex-builder.md) and [Grep Builder](grep-builder.md), cannot add results.

A result is a snapshot of the tool's report at the moment you add it, stamped with the local date and time. Running the tool again later does not change it; add the new run as another result.

## Reading the results

The detail area for the selected project shows:

1. **Name** and **Notes**.
2. The **Export all** bar, the notes target button and **Delete project**.
3. **Results (N)**: a numbered list. Each entry shows its title, then a line with the tool name, when it was added and the report's section titles, then its note box.
4. **Notes (N)**: timestamped tool notes grouped by tool, oldest first, with **Edit** and **Delete**. A note tied to a result shows "About result N: TITLE". How notes are written is covered in [Projects and notes](../projects-and-notes.md).

### Worked example

Project "Branch 12 VPN drops", Notes: "Ticket CHG-1042. Site tunnel to 203.0.113.1." Results added in this order:

1. [MTU Calculator](mtu-calculator.md): "MTU: IPsec ESP" (inner MTU 1446)
2. [Traceroute](traceroute.md) to 203.0.113.1
3. [Packet Filter Builder](filter-builder.md): sniffer command for the tunnel peer

Move the traceroute to the top with its up arrow, add the note "Path MTU test from the branch side" to it, and export as PDF. The PDF starts with an **Overview** (project name, number of results and notes, your project notes, and a contents table with #, Result, Tool and Added), followed by one part per result in your order: its number and title, the tool and time added, the result note, then that tool's report sections. Each tool's notes follow the last result from that tool. Tools that have notes but no saved result get a "Notes only, no saved output" part at the end.

## What the results do and do not tell you

- A project holds copies of reports, not live data. It does not rerun anything.
- Limits: 1,000 projects, 500 results per project, 2,000 notes per project, and about 25 MB per project file.
- A plain export file name is the project name. Redacted exports use the neutral name `project-redacted` because the project name is often a customer.

## Online activity and privacy

None. Projects are stored as JSON files in a `projects` folder under the app's data directory on this computer. Nothing is uploaded. Saved results contain whatever the tool's report contained, which can include hostnames, addresses and findings, so treat project files and exports as sensitive. Use **Redacted...** before sharing. See [Privacy](../privacy.md).

## Export and projects

Export formats are HTML, PDF, Markdown and Plain text for the whole project, plus **Redacted...** with a preview of what will be replaced. The report contains the Overview, every result in order with its title, tool, time added and note, each result's original report sections, and the tool notes. Details of redaction options are in [Export and redaction](../export-and-redaction.md).

## Platform notes

The app data directory is the OS default for the app (under `~/Library/Application Support` on macOS, `%APPDATA%` on Windows and `~/.local/share` on Linux). The save dialog is the native one for each OS.

## Troubleshooting

**"project is full (limit 500 results)".** Remove results or start a second project.

**"too many projects (limit 1000); delete some first".** Delete old projects.

**"project would be too large (N bytes; limit 25000000)".** The new result would push the project past about 25 MB. Start a new project for further results.

**"name is too long (limit 200 characters)" or "notes are too long (limit 20000 characters)".** Shorten the text.

**"project not found".** The project file no longer exists. Select another project.

**"could not locate the app data folder: ..."** The OS did not report an app data directory, so projects cannot be stored. Check the user profile and home directory permissions.

**"project file is unreadable: ..."** The JSON file on disk is damaged or was edited by hand. Restore it from a backup or delete the project.

**Export all buttons are greyed out.** The project has no results and no notes yet. Redacted export also needs at least one result.

## Related tools

- [Subnet Calculator](subnet-calculator.md)
- [DNS Analyzer](dns-analyzer.md)
- [TLS Inspector](tls-inspector.md)
- [Port Scanner](port-scanner.md)
- [Traceroute](traceroute.md)
