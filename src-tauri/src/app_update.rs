//! How this copy of the app can be updated. The update check and install
//! themselves run in the updater plugin (signed manifests from the GitHub
//! release, verified against the public key in `tauri.conf.json`); this
//! only tells the UI whether installing in place is possible here.

use serde::Serialize;

/// Where the app was installed from, as far as updating goes.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UpdateKind {
    /// macOS app, Windows installer or Linux AppImage: updates in place.
    InPlace,
    /// Linux .deb or .rpm: the package manager owns the files.
    Package,
}

fn kind_for(os: &str, appimage: bool) -> UpdateKind {
    if os == "linux" && !appimage {
        UpdateKind::Package
    } else {
        UpdateKind::InPlace
    }
}

/// Whether this copy can install updates itself.
#[tauri::command]
pub fn update_kind() -> UpdateKind {
    kind_for(std::env::consts::OS, std::env::var_os("APPIMAGE").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_packages_cannot_update_in_place() {
        assert_eq!(kind_for("linux", false), UpdateKind::Package);
        assert_eq!(kind_for("linux", true), UpdateKind::InPlace);
        assert_eq!(kind_for("macos", false), UpdateKind::InPlace);
        assert_eq!(kind_for("windows", false), UpdateKind::InPlace);
    }
}
