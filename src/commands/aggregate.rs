use crate::aggregator;

pub fn run(path: String, window_secs: u64) -> Result<(), String> {
    let input = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read aggregate input file {path}: {err}"))?;
    let records = aggregator::aggregate_text(&input, window_secs)?;

    for record in records {
        println!("{}", record.render());
    }

    Ok(())
}
