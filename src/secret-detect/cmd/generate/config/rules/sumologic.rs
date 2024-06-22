use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn sumologic_access_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.".to_string(),
        rule_id: "sumologic-access-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["sumo"], r"su[a-zA-Z0-9]{12}", false)).unwrap(),
        tags: vec![],
        keywords: vec!["sumo".to_string()],
        allowlist: Allowlist {
            regex_target: "line".to_string(),
            regexes: vec![Regex::new(r"sumOf").unwrap()],
            ..Allowlist::default()
        },
        entropy: Some(3.0),
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"sumologic.accessId = "su9OL59biWiJu7""#,      
        r#"sumologic_access_id = "sug5XpdpaoxtOH""#,     
        r#"export SUMOLOGIC_ACCESSID="suDbJw97o9WVo0""#, 
        r#"SUMO_ACCESS_ID = "suGyI5imvADdvU""#,          
        generate_sample_secret("sumo", &format!("su{}", secrets::new_secret(&alpha_numeric("12")))), 
    ];
    let false_positives = vec![
        r#"- (NSNumber *)sumOfProperty:(NSString *)property;"#,
        r#"- (NSInteger)sumOfValuesInRange:(NSRange)range;"#,
        r#"+ (unsigned char)byteChecksumOfData:(id)arg1;"#,
        r#"sumOfExposures = sumOfExposures;"#, 
        r#".si-sumologic.si--color::before { color: #000099; }"#,
        r#"/// Based on the SumoLogic keyword syntax:"#,
        r#"sumologic_access_id         = """#,
        r#"SUMOLOGIC_ACCESSID: ${SUMOLOGIC_ACCESSID}"#,
        r#"export SUMOLOGIC_ACCESSID=XXXXXXXXXXXXXX"#, 
    ];

    validate(rule, &test_positives, Some(&false_positives))
}

pub fn sumologic_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.".to_string(),
        rule_id: "sumologic-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["sumo"], &alpha_numeric("64"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["sumo".to_string()],
        allowlist: Allowlist::default(),
        entropy: Some(3.0),
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"export SUMOLOGIC_ACCESSKEY="3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx""#, 
        r#"SUMO_ACCESS_KEY: gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk"#,             
        r#"SUMOLOGIC_ACCESSKEY: 9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7"#,         
        r#"sumo_access_key = "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5""#,          
        generate_sample_secret("sumo", &secrets::new_secret(&alpha_numeric("64"))), 
    ];
    let false_positives = vec![
        r#"#   SUMO_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"#, 
        "-e SUMO_ACCESS_KEY=`etcdctl get /sumologic_secret`",
        r#"SUMO_ACCESS_KEY={SumoAccessKey}"#,
        r#"SUMO_ACCESS_KEY=${SUMO_ACCESS_KEY:=$2}"#,
        r#"sumo_access_key   = "<SUMOLOGIC ACCESS KEY>""#,
        "SUMO_ACCESS_KEY: AbCeFG123",
    ];

    validate(rule, &test_positives, Some(&false_positives))
}