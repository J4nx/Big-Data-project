from pyspark.sql.types import StringType
from pyspark.sql.functions import udf, col, lower, regexp_replace, split, when, lit


def vulnerability_assessment(version):
    """
    Assess vulnerability based on version information.
    """
    if version:
        try:
            parts = version.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0

            if major == 9:
                return "likely_vulnerable (Pulse Connect Secure 9.x)"
            if major < 22:
                return "likely_vulnerable (old version < 22)"
            if major == 22 and minor <= 7:
                return "likely_vulnerable (old version 22.7 or older)"

            return "not_vulnerable (newer version)"
        except (ValueError, IndexError):
            return "invalid_version_format"
    return None


def process_shodan_data(df):
    """
    Process Shodan Spark DataFrame: normalize, assess vulnerabilities, filter and prioritize.

    Args:
        df (DataFrame): Spark DataFrame from Shodan data.

    Returns:
        DataFrame: Processed and filtered Spark DataFrame.
    """
    vuln_assess_udf = udf(vulnerability_assessment, StringType())

    normalized_org = lower(regexp_replace(col("org"), "[()]", ""))
    normalized_isp = lower(regexp_replace(col("isp"), "[()]", ""))
    first_word_org = split(normalized_org, "\\s+").getItem(0)
    first_word_isp = split(normalized_isp, "\\s+").getItem(0)

    if "version" in df.columns:
        df = df.withColumn("vulnerability_assessment", vuln_assess_udf(col("version")))
    else:
        df = df.withColumn("vulnerability_assessment", lit(None))

    filtered_df = df.filter(
        (col("http.status") == 200) & (col("product") == "Pulse Secure") &
        (
            (col("cpe23").isNull()) |
            (first_word_org != first_word_isp) |
            (col("version").isNotNull() if "version" in df.columns else lit(False))
        )
    )

    filtered_df = filtered_df.withColumn(
        "priority",
        when(col("vulnerability_assessment").startswith("likely_vulnerable"), lit(1))
        .when((col("cpe23").isNull()) & (first_word_org != first_word_isp), lit(2))
        .when((col("cpe23").isNull()) & (first_word_org == first_word_isp), lit(3))
        .otherwise(lit(4))
    )

    return filtered_df.orderBy(col("priority").asc())
