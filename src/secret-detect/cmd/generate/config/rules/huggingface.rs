use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn hugging_face_access_token() -> Rule {
    let rule = Rule {
        description: "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.".to_string(),
        rule_id: "huggingface-access-token".to_string(),
        regex: Regex::new(r#"(?:^|[\'"` >=:])(hf_[a-zA-Z]{34})(?:$|[\'"` <])"#).unwrap(),
        tags: vec![],
        keywords: vec!["hf_".to_string()],
        allowlist: Allowlist::default(),
        entropy: Some(1.0),
        secret_group: None,
    };

    let test_positives = vec![
        r#"huggingface-cli login --token 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"#,
        r#"huggingface-cli login --token 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"#,
        r#"huggingface-cli login --token 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"#,
        r#"huggingface-cli login --token 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"#,
        r#"huggingface-cli login --token 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"#,
        r#"huggingface-cli login --token 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"#,
        r#"huggingface-cli login --token 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"#,
        r#"huggingface-cli login --token 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"#,
        r#"-H "Authorization: Bearer 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""#,
        r#"DEV=1 HF_TOKEN=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 poetry run python app.py"#,
        r#"use_auth_token='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')"#,
        r#"CI_HUB_USER_TOKEN = "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""#,
        r#"- Change line 5 and add your Hugging Face token, that is, instead of 'hf_token = "ADD_YOUR_HUGGING_FACE_TOKEN_HERE"', you will need to change it to something like'hf_token = "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"'"#,
        r#""    hf_token = \"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\"\n","#,
        r#"# Not critical, only usable on the sandboxed CI instance.
		TOKEN = "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""#,
        r#"    parser.add_argument("--hf_token", type=str, default='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', help="Hugging Face Access Token to access PyAnnote gated models")"#,
    ];
    let false_positives = vec![
        r#"- (id)hf_requiredCharacteristicTypesForDisplayMetadata;"#,
        r#"amazon.de#@#div[data-cel-widget="desktop-rhf_SponsoredProductsRemoteRHFSearchEXPSubsK2ClickPagination"]"#,
        r#"                            _kHMSymptomhf_generatedByHomeAppForDebuggingPurposesKey,"#,
        r#"    #define OSCHF_DebugGetExpectedAverageCrystalAmplitude NOROM_OSCHF_DebugGetExpectedAverageCrystalAmplitude"#,
        r#"  M_UINT       (ServingCellPriorityParametersDescription_t,  H_PRIO,  2, &hf_servingcellpriorityparametersdescription_h_prio),"#,
        r#"+HWI-ST565_0092:4:1101:5508:5860#ACTTGA/1
		bb_eeeeegfgffhiiiiiiiiiiihiiiiicgafhf_eefghihhiiiifhifhhdhifhiiiihifdgdhggf\bbceceedbcd
		@HWI-ST565_0092:4:1101:7621:5770#ACTTGA/1"#,
        r#"y{}x|~|}  {~}}~|  ~}||�~|� {��|  {} {|~z{}{{|{||{|}|{}{~|y}vjoePbUBJ7&;" ;  <  ;  :  ;  ?!!;  <  7%$IACa_ecghbfbaebejhahfbhf_ddbficghbgfbhhcghdghfhigiifhhehhdggcgfchf_fgcei^[[.40&54"56 66 6"#,
        r#"                    change_dir(cwd)
		subdirs = glob.glob('HF_CAASIMULIAComputeServicesBuildTime.HF*.Linux64')
		if len(subdirs) == 1:"#,
        r#"        os.environ.get("HF_AUTH_TOKEN",
		"hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),"#,
        r#"# HuggingFace API Token https://huggingface.co/settings/tokens
		HUGGINGFACE_API_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,"#,
    ];

    validate(rule, &test_positives, Some(&false_positives))
}

pub fn hugging_face_organization_api_token() -> Rule {
    let rule = Rule {
        description: "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.".to_string(),
        rule_id: "huggingface-organization-api-token".to_string(),
        regex: Regex::new(r#"(?:^|[\'"` >=:\(,)])(api_org_[a-zA-Z]{34})(?:$|[\'"` <\),])"#).unwrap(),
        tags: vec![],
        keywords: vec!["api_org_".to_string()],
        allowlist: Allowlist::default(),
        entropy: Some(2.0),
        secret_group: None,
    };

    let test_positives = vec![
        r#"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"#,
        r#"`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`"#,
        r#"\'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'\"#,
        r#"\"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\""#,
        r#",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,"#,
        r#"(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)"#,
        r#"<foo>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</foo>"#,
        r#"def test_private_space(self):
        hf_token = "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"  # Intentionally revealing this key for testing purposes
        io = gr.load("#,
        r#"hf_token = "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"  # Intentionally revealing this key for testing purposes"#,
        r#""news_train_dataset = datasets.load_dataset('nlpHakdang/aihub-news30k',  data_files = "train_news_text.csv", use_auth_token='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')\n""#,
        r#"os.environ['HUGGINGFACEHUB_API_TOKEN'] = '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'"#,
        &format!("api_org_{}", secrets::new_secret(r"[a-zA-Z]{34}")),
    ];
    let false_positives = vec![
        r#"public static final String API_ORG_EXIST = "APIOrganizationExist";"#,
        r#"const api_org_controller = require('../../controllers/api/index').organizations;"#,
        r#"API_ORG_CREATE("https://qyapi.weixin.qq.com/cgi-bin/department/create?access_token=ACCESS_TOKEN"),"#,
        r#"def test_internal_api_org_inclusion_with_href(api_name, href, expected, monkeypatch, called_with):
		monkeypatch.setattr("requests.sessions.Session.request", called_with)"#,
        r#"    def _api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a(self, method, url, body, headers):
        body = self.fixtures.load("api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a.xml")
        return httplib.OK, body, headers, httplib.responses[httplib.OK]"#,
        r#"<p>You should see a token <code>hf_xxxxx</code> (old tokens are <code>api_XXXXXXXX</code> or <code>api_org_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</code>).</p>"#,
        r#"  From Hugging Face docs:
		You should see a token hf_xxxxx (old tokens are api_XXXXXXXX or api_org_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx).
		If you do not submit your API token when sending requests to the API, you will not be able to run inference on your private models."#,
    ];

    validate(rule, &test_positives, Some(&false_positives))
}