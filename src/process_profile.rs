//! Named application families carried through the existing process-rule ABI.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessProfile {
    WeGame,
}

impl ProcessProfile {
    /// Reserved selectors contain `:`, which cannot appear in a Windows exe name.
    pub const fn rule(self) -> &'static str {
        match self {
            Self::WeGame => "@group:wegame",
        }
    }

    #[cfg(any(windows, test))]
    pub(crate) fn matches_names(self, names: &[String]) -> bool {
        names.iter().any(|name| {
            matches!(
                crate::normalize_process_name(name).as_str(),
                "wegame"
                    | "wegame_env"
                    | "wegame_launcher"
                    | "wegamelauncher"
                    | "tgp"
                    | "tcls_core"
                    | "leagueclient"
                    | "leagueclientux"
                    | "leagueclientuxrender"
                    | "league of legends"
                    | "riotclientservices"
                    | "sguard"
                    | "sguard64"
                    | "sguardsvc"
                    | "sguardsvc64"
                    | "ace-service"
                    | "ace-service64"
            )
        })
    }

    #[cfg(any(windows, test))]
    pub(crate) fn matches_path(self, path: &str) -> bool {
        // Match complete directory components, never substrings such as
        // `NotWeGame`, and never turn the shared `services.exe` parent direct.
        path.replace('/', "\\").rsplit_once('\\').is_some_and(|(directories, _)| {
            directories.split('\\').any(|part| {
                part.eq_ignore_ascii_case("wegame")
                    || part.eq_ignore_ascii_case("wegameapps")
                    || part.eq_ignore_ascii_case("anticheatexpert")
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wegame_covers_launcher_children_and_independent_game_services_only() {
        let profile = ProcessProfile::WeGame;
        for names in [
            vec!["UnknownNewGame.exe", "WeGame.exe"],
            vec!["SGuard64.exe", "services.exe"],
            vec!["LeagueClient.exe"],
        ] {
            assert!(profile.matches_names(&names.into_iter().map(str::to_owned).collect::<Vec<_>>()));
        }
        assert!(profile.matches_path(r"E:\WeGameApps\NewGame\Bin\game.exe"));
        assert!(profile.matches_path(r"C:\Program Files\AntiCheatExpert\SGuard\x64\helper.exe"));
        assert!(!profile.matches_path(r"C:\Tools\NotWeGame\helper.exe"));
        assert!(!profile.matches_names(&["unrelated.exe".into(), "services.exe".into()]));
        assert!(!profile.matches_names(&["client.exe".into(), "launcher.exe".into()]));
    }
}
