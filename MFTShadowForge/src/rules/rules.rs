use regex::Regex;

/// Предкомпилированное glob-правило.
#[derive(Debug, Clone)]
pub struct GlobRule {
    pub regex: Regex,
}

impl GlobRule {
    pub fn new(pattern: impl AsRef<str>) -> Result<Self, regex::Error> {
        let pattern_lc = pattern.as_ref().to_ascii_lowercase();
        let escaped = regex::escape(&pattern_lc);
        let regex_str = escaped.replace("\\*", ".*").replace("\\?", ".");
        let final_pattern = format!("^{}$", regex_str);
        Ok(Self {
            regex: Regex::new(&final_pattern)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Rule {
    Matches(GlobRule),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
    And(Box<Rule>, Box<Rule>),
    Not(Box<Rule>),
}

impl Rule {
    pub fn glob(pattern: impl AsRef<str>) -> Result<Self, regex::Error> {
        Ok(Rule::Matches(GlobRule::new(pattern)?))
    }

    pub fn starts_with(s: impl Into<String>) -> Self {
        Rule::StartsWith(s.into().to_ascii_lowercase())
    }

    pub fn ends_with(s: impl Into<String>) -> Self {
        Rule::EndsWith(s.into().to_ascii_lowercase())
    }

    pub fn contains(s: impl Into<String>) -> Self {
        Rule::Contains(s.into().to_ascii_lowercase())
    }

    pub fn and(self, other: Rule) -> Self {
        Rule::And(Box::new(self), Box::new(other))
    }

    pub fn not(self) -> Self {
        Rule::Not(Box::new(self))
    }

    /// Быстрая проверка - вход уже в нижнем регистре.
    pub fn check_lowered(&self, input_lc: &str) -> bool {
        match self {
            Rule::StartsWith(s) => input_lc.starts_with(s),
            Rule::EndsWith(s) => input_lc.ends_with(s),
            Rule::Contains(s) => input_lc.contains(s),
            Rule::Matches(g) => g.regex.is_match(input_lc),
            Rule::And(l, r) => l.check_lowered(input_lc) && r.check_lowered(input_lc),
            Rule::Not(inner) => !inner.check_lowered(input_lc),
        }
    }

    #[allow(dead_code)]
    pub fn check(&self, input: &str) -> bool {
        self.check_lowered(&input.to_ascii_lowercase())
    }
}