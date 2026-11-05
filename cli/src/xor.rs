use super::*;
use std::io::{self, Write};

pub fn write_xor_text(result: &XorResult, writer: &mut dyn Write) -> io::Result<()> {
    writeln!(
        writer,
        "{:#010x}\tXOR\tkey={}\tscore={:.3}\t{}",
        result.offset,
        hex_encode(&result.key),
        result.score,
        String::from_utf8_lossy(&result.plaintext)
    )
}

pub fn write_xor_json(
    result: &XorResult,
    writer: &mut dyn Write,
    result_count: &mut usize,
    layout: JsonLayout,
) -> io::Result<()> {
    json_record_open(writer, result_count, layout, Some("xor"))?;
    write!(
        writer,
        "\"group\":\"XOR\",\"offset\":{},\"key\":{},\"score\":{:.6},\"plaintext\":{}}}",
        result.offset,
        json_escape(&hex_encode(&result.key)),
        result.score,
        json_escape(&String::from_utf8_lossy(&result.plaintext))
    )?;
    *result_count += 1;
    Ok(())
}
