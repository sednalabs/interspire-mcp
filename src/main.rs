use interspire_mcp::{
    run_audience_hygiene_export, run_audience_hygiene_export_begin,
    run_audience_hygiene_export_resume, run_audience_hygiene_export_status,
    AudienceHygieneExportBeginRequest, AudienceHygieneExportRequest,
    AudienceHygieneExportResumeRequest, AudienceHygieneExportStatusRequest, InterspireMcpServer,
    InterspireServerConfig, DEFAULT_HYGIENE_QUERY_BUDGET,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let Some(command) = args.first().map(String::as_str) {
        match command {
            "audience-hygiene-export" => {
                if args[1..].iter().any(|arg| arg == "--help" || arg == "-h") {
                    println!("{}", audience_hygiene_export_usage());
                    return Ok(());
                }
                let request = parse_audience_hygiene_export_args(&args[1..])?;
                let report =
                    run_audience_hygiene_export(InterspireServerConfig::from_env(), &request)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            "audience-hygiene-export-begin" => {
                if args[1..].iter().any(|arg| arg == "--help" || arg == "-h") {
                    println!("{}", audience_hygiene_export_begin_usage());
                    return Ok(());
                }
                let request = parse_audience_hygiene_export_begin_args(&args[1..])?;
                let report = run_audience_hygiene_export_begin(
                    InterspireServerConfig::from_env(),
                    &request,
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            "audience-hygiene-export-resume" => {
                if args[1..].iter().any(|arg| arg == "--help" || arg == "-h") {
                    println!("{}", audience_hygiene_export_resume_usage());
                    return Ok(());
                }
                let request = parse_audience_hygiene_export_resume_args(&args[1..])?;
                let report = run_audience_hygiene_export_resume(
                    InterspireServerConfig::from_env(),
                    &request,
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            "audience-hygiene-export-status" => {
                if args[1..].iter().any(|arg| arg == "--help" || arg == "-h") {
                    println!("{}", audience_hygiene_export_status_usage());
                    return Ok(());
                }
                let request = parse_audience_hygiene_export_status_args(&args[1..])?;
                let report = run_audience_hygiene_export_status(
                    InterspireServerConfig::from_env(),
                    &request,
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            _ => {}
        }
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
            "--max-queries-per-call" => {
                required_value(args, index, "--max-queries-per-call")?;
                index += 2;
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

fn parse_audience_hygiene_export_begin_args(
    args: &[String],
) -> Result<AudienceHygieneExportBeginRequest, String> {
    let export = parse_audience_hygiene_export_args(args)?;
    let max_queries_per_call =
        parse_optional_query_budget(args)?.unwrap_or(DEFAULT_HYGIENE_QUERY_BUDGET);
    Ok(AudienceHygieneExportBeginRequest {
        source_list_ids: export.source_list_ids,
        output_dir: export.output_dir,
        artifact_prefix: export.artifact_prefix,
        include_sqlite: export.include_sqlite,
        max_queries_per_call,
    })
}

fn parse_audience_hygiene_export_resume_args(
    args: &[String],
) -> Result<AudienceHygieneExportResumeRequest, String> {
    let mut job_id = None;
    let mut output_dir = None;
    let mut artifact_prefix = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--job-id" => {
                job_id = Some(required_value(args, index, "--job-id")?.to_string());
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
            "--max-queries-per-call" => {
                index += 2;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(AudienceHygieneExportResumeRequest {
        job_id: job_id.ok_or_else(|| "missing --job-id".to_string())?,
        output_dir,
        artifact_prefix,
        max_queries_per_call: parse_optional_query_budget(args)?
            .unwrap_or(DEFAULT_HYGIENE_QUERY_BUDGET),
    })
}

fn parse_audience_hygiene_export_status_args(
    args: &[String],
) -> Result<AudienceHygieneExportStatusRequest, String> {
    let mut job_id = None;
    let mut output_dir = None;
    let mut artifact_prefix = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--job-id" => {
                job_id = Some(required_value(args, index, "--job-id")?.to_string());
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
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(AudienceHygieneExportStatusRequest {
        job_id: job_id.ok_or_else(|| "missing --job-id".to_string())?,
        output_dir,
        artifact_prefix,
    })
}

fn parse_optional_query_budget(args: &[String]) -> Result<Option<usize>, String> {
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--max-queries-per-call" => {
                let raw = required_value(args, index, "--max-queries-per-call")?;
                let value = raw
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --max-queries-per-call: {raw}"))?;
                return Ok(Some(value));
            }
            "--source-list-ids" | "--output-dir" | "--artifact-prefix" | "--job-id" => {
                index += 2;
            }
            "--no-sqlite" => {
                index += 1;
            }
            _ => {
                index += 1;
            }
        }
    }
    Ok(None)
}

fn required_value<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| format!("missing value for {}", name))
}

fn audience_hygiene_export_usage() -> String {
    "usage: interspire-mcp audience-hygiene-export --source-list-ids 7,8 --output-dir /secure/private/interspire-audience-hygiene --artifact-prefix example-run\n\nSet INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private before writing recipient artifacts."
        .to_string()
}

fn audience_hygiene_export_begin_usage() -> String {
    "usage: interspire-mcp audience-hygiene-export-begin --source-list-ids 7,8 --output-dir /secure/private/interspire-audience-hygiene --artifact-prefix example-run --max-queries-per-call 4"
        .to_string()
}

fn audience_hygiene_export_resume_usage() -> String {
    "usage: interspire-mcp audience-hygiene-export-resume --job-id iah_123 --output-dir /secure/private/interspire-audience-hygiene [--artifact-prefix legacy-prefix] --max-queries-per-call 4"
        .to_string()
}

fn audience_hygiene_export_status_usage() -> String {
    "usage: interspire-mcp audience-hygiene-export-status --job-id iah_123 --output-dir /secure/private/interspire-audience-hygiene [--artifact-prefix legacy-prefix]"
        .to_string()
}
