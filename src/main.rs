use interspire_6_mcp::{
    run_audience_hygiene_export, AudienceHygieneExportRequest, InterspireMcpServer,
    InterspireServerConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|arg| arg == "audience-hygiene-export")
    {
        if args[1..].iter().any(|arg| arg == "--help" || arg == "-h") {
            println!("{}", audience_hygiene_export_usage());
            return Ok(());
        }
        let request = parse_audience_hygiene_export_args(&args[1..])?;
        let report = run_audience_hygiene_export(InterspireServerConfig::from_env(), &request)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let server = InterspireMcpServer::new(InterspireServerConfig::from_env())?;
    mcp_toolkit::server::stdio::serve_stdio(server).await?;
    Ok(())
}

fn parse_audience_hygiene_export_args(
    args: &[String],
) -> Result<AudienceHygieneExportRequest, String> {
    let mut source_list_ids = Vec::new();
    let mut output_dir = None;
    let mut artifact_prefix = None;
    let mut include_sqlite = true;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--source-list-ids" => {
                let raw = required_value(args, index, "--source-list-ids")?;
                source_list_ids = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| {
                        value
                            .parse::<u64>()
                            .map_err(|_| format!("invalid list id in --source-list-ids: {value}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                index += 2;
            }
            "--output-dir" => {
                output_dir = Some(required_value(args, index, "--output-dir")?.to_string());
                index += 2;
            }
            "--artifact-prefix" => {
                artifact_prefix =
                    Some(required_value(args, index, "--artifact-prefix")?.to_string());
                index += 2;
            }
            "--no-sqlite" => {
                include_sqlite = false;
                index += 1;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    if source_list_ids.is_empty() {
        return Err("missing --source-list-ids".to_string());
    }

    Ok(AudienceHygieneExportRequest {
        source_list_ids,
        output_dir,
        artifact_prefix,
        include_sqlite,
    })
}

fn required_value<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| format!("missing value for {}", name))
}

fn audience_hygiene_export_usage() -> String {
    "usage: interspire-6-mcp audience-hygiene-export --source-list-ids 7,8 --output-dir /secure/private/interspire-audience-hygiene --artifact-prefix example-run\n\nSet INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private before writing recipient artifacts."
        .to_string()
}
