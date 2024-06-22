use regex::Regex;

fn any_regex_match(f: &str, res: &[&Regex]) -> bool {
    for re in res {
        if re.is_match(f) {
            return true;
        }
    }
    false
}

fn regex_matched(f: &str, re: &Option<&Regex>) -> bool {
    if let Some(re) = re {
        re.is_match(f)
    } else {
        false
    }
}
