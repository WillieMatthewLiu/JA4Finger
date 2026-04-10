use crate::aggregator;

pub fn run(path: String) -> Result<(), String> {
    let input = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read aggregate input file {path}: {err}"))?;
    let records = aggregator::aggregate_text(&input)?;

    for record in records {
        println!("{}", record.render());
    }

    Ok(())
}
