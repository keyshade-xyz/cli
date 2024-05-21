use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use log::{error, info};

use crate::config::{Allowlist, Config, Rule};
use crate::rules::*;

// Assuming rules module contains all the rule functions

const TEMPLATE_PATH: &str = "rules/config.tmpl";

// Entry point for generating the gitleaks.toml configuration file
pub fn generate_config_file(output_path: &str) {
    let mut config = Config::default();
    config.rules = build_rule_lookup();

    if let Err(e) = write_config_to_file(&config, output_path) {
        error!("Failed to write config to file: {}", e);
    } else {
        info!("Successfully generated keyshade.toml at {}", output_path);
    }
}

// Build a HashMap of rules, ensuring unique rule ID
fn build_rule_lookup() -> HashMap<String, Rule> {
    let mut rule_lookup = HashMap::new();
    
    // Macro to add rules to the lookup table
    macro_rules! add_rule {
        ($rule_fn:ident) => {
            let rule = $rule_fn();
            if rule_lookup.insert(rule.rule_id.clone(), rule).is_some() {
                error!("Rule ID {} is not unique", rule.rule_id);
            }
        };
    }

    // Add each rule using the macro
    aadd_rule!(adafruit_api_key);
    add_rule!(adobe_client_id);
    add_rule!(adobe_client_secret);
    add_rule!(age_secret_key);
    add_rule!(airtable);
    add_rule!(algolia_api_key);
    add_rule!(alibaba_access_key);
    add_rule!(alibaba_secret_key);
    add_rule!(asana_client_id);
    add_rule!(asana_client_secret);
    add_rule!(atlassian);
    add_rule!(authress);
    add_rule!(aws);
    add_rule!(beamer);
    add_rule!(bitbucket_client_id);
    add_rule!(bitbucket_client_secret);
    add_rule!(bittrex_access_key);
    add_rule!(bittrex_secret_key);
    add_rule!(clojars);
    add_rule!(cloudflare_global_api_key);
    add_rule!(cloudflare_api_key);
    add_rule!(cloudflare_origin_ca_key);
    add_rule!(codecov_access_token);
    add_rule!(coinbase_access_token);
    add_rule!(confluent_secret_key);
    add_rule!(confluent_access_token);
    add_rule!(contentful);
    add_rule!(databricks);
    add_rule!(datadogtoken_access_token);
    add_rule!(defined_networking_api_token);
    add_rule!(digitalocean_pat);
    add_rule!(digitalocean_oauth_token);
    add_rule!(digitalocean_refresh_token);
    add_rule!(discord_api_token);
    add_rule!(discord_client_id);
    add_rule!(discord_client_secret);
    add_rule!(doppler);
    add_rule!(drop_box_api_secret);
    add_rule!(drop_box_long_lived_api_token);
    add_rule!(drop_box_short_lived_api_token);
    add_rule!(droneci_access_token);
    add_rule!(duffel);
    add_rule!(dynatrace);
    add_rule!(easy_post);
    add_rule!(easy_post_test_api);
    add_rule!(etsy_access_token);
    add_rule!(facebook_secret);
    add_rule!(facebook_access_token);
    add_rule!(facebook_page_access_token);
    add_rule!(fastly_api_token);
    add_rule!(finicity_api_token);
    add_rule!(finicity_client_secret);
    add_rule!(finnhub_access_token);
    add_rule!(flickr_access_token);
    add_rule!(flutterwave_enc_key);
    add_rule!(flutterwave_public_key);
    add_rule!(flutterwave_secret_key);
    add_rule!(frame_io);
    add_rule!(freshbooks_access_token);
    add_rule!(gcp_api_key);
    add_rule!(gcp_service_account);
    add_rule!(generic_credential);
    add_rule!(github_app);
    add_rule!(github_fine_grained_pat);
    add_rule!(github_oauth);
    add_rule!(github_pat);
    add_rule!(github_refresh);
    add_rule!(gitlab_pat);
    add_rule!(gitlab_pipeline_trigger_token);
    add_rule!(gitlab_runner_registration_token);
    add_rule!(hashicorp);
    add_rule!(hashicorp_field);
    add_rule!(heroku);
    add_rule!(hubspot);
    add_rule!(hugging_face_access_token);
    add_rule!(hugging_face_organization_api_token);
    add_rule!(infracost_api_token);
    add_rule!(intercom);
    add_rule!(jfrog_api_key);
    add_rule!(jfrog_identity_token);
    add_rule!(jwt);
    add_rule!(jwt_base64);
    add_rule!(kraken_access_token);
    add_rule!(kucoin_access_token);
    add_rule!(kucoin_secret_key);
    add_rule!(launchdarkly_access_token);
    add_rule!(linear_api_token);
    add_rule!(linear_client_secret);
    add_rule!(linkedin_client_id);
    add_rule!(linkedin_client_secret);
    add_rule!(lob_api_token);
    add_rule!(lob_pub_api_token);
    add_rule!(mailchimp);
    add_rule!(mailgun_private_api_token);
    add_rule!(mailgun_pub_api_token);
    add_rule!(mailgun_signing_key);
    add_rule!(mapbox);
    add_rule!(mattermost_access_token);
    add_rule!(messagebird_api_token);
    add_rule!(messagebird_client_id);
    add_rule!(netlify_access_token);
    add_rule!(new_relic_browser_api_key);
    add_rule!(new_relic_user_id);
    add_rule!(new_relic_user_key);
    add_rule!(npm);
    add_rule!(nytimes_access_token);
    add_rule!(okta_access_token);
    add_rule!(openai);
    add_rule!(plaid_access_id);
    add_rule!(plaid_secret_key);
    add_rule!(plaid_access_token);
    add_rule!(planetscale_api_token);
    add_rule!(planetscale_oauth_token);
    add_rule!(planetscale_password);
    add_rule!(postman_api);
    add_rule!(prefect);
    add_rule!(private_key);
    add_rule!(pulumi_api_token);
    add_rule!(pypi_upload_token);
    add_rule!(rapidapi_access_token);
    add_rule!(readme);
    add_rule!(rubygems_api_token);
    add_rule!(scalingo_api_token);
    add_rule!(sendbird_access_id);
    add_rule!(sendbird_access_token);
    add_rule!(sendgrid_api_token);
    add_rule!(sendinblue_api_token);
    add_rule!(sentry_access_token);
    add_rule!(shippo_api_token);
    add_rule!(shopify_access_token);
    add_rule!(shopify_custom_access_token);
    add_rule!(shopify_private_app_access_token);
    add_rule!(shopify_shared_secret);
    add_rule!(sidekiq_secret);
    add_rule!(sidekiq_sensitive_url);
    add_rule!(slack_app_level_token);
    add_rule!(slack_bot_token);
    add_rule!(slack_configuration_refresh_token);
    add_rule!(slack_configuration_token);
    add_rule!(slack_legacy_bot_token);
    add_rule!(slack_legacy_token);
    add_rule!(slack_legacy_workspace_token);
    add_rule!(slack_user_token);
    add_rule!(slack_webhook_url);
    add_rule!(snyk);
    add_rule!(square_access_token);
    add_rule!(square_secret);
    add_rule!(squarespace_access_token);
    add_rule!(sumologic_access_id);
    add_rule!(sumologic_access_token);
    add_rule!(teams_webhook);
    add_rule!(telegram_bot_token);
    add_rule!(travis_ci_access_token);
    add_rule!(trello_access_token);
    add_rule!(twilio);
    add_rule!(twitch_api_token);
    add_rule!(twitter_api_key);
    add_rule!(twitter_api_secret);
    add_rule!(twitter_access_secret);
    add_rule!(twitter_access_token);
    add_rule!(twitter_bearer_token);
    add_rule!(typeform);
    add_rule!(vault_batch_token);
    add_rule!(vault_service_token);
    add_rule!(yandex_api_key);
    add_rule!(yandex_aws_access_token);
    add_rule!(yandex_access_token);
    add_rule!(zendesk_secret_key);

    rule_lookup
}

// Write the configuration to a TOML file
fn write_config_to_file(config: &Config, output_path: &str) -> Result<(), std::io::Error> {
    let template = include_str!(TEMPLATE_PATH);
    let rendered_config = match tera::Tera::one_off(template, &tera::Context::from_serialize(config).unwrap(), true) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to render config template: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Template rendering failed"));
        }
    };

    let mut file = File::create(output_path)?;
    file.write_all(rendered_config.as_bytes())?;

    Ok(())
}