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

def ensure_columns_exist(df, columns_needed):
    """
    Add missing columns with null values.
    """
    for column in columns_needed:
        if column not in df.columns:
            df = df.withColumn(column, lit(None))
    return df


def process_shodan_data(df):
    """
    Process Shodan Spark DataFrame: normalize, assess vulnerabilities, filter, prioritize, and select essential columns.
    """

    vuln_assess_udf = udf(vulnerability_assessment, StringType())

    # --- Flatten nested fields if they exist ---
    nested_mappings = {
        "country_name": "location.country_name",
        "city": "location.city",
        "CN": "ssl.cert.subject.CN",
        "O": "ssl.cert.issuer.O"
    }
    for new_col, nested_col in nested_mappings.items():
        if nested_col.split('.')[0] in df.columns:
            df = df.withColumn(new_col, col(nested_col))

    # --- Early select only existing columns ---
    columns_needed = [
        "http.status", "ip_str", "org", "isp", "domains", "version", "product",
        "cpe23", "country_name", "city", "CN", "O", "timestamp"
    ]
    df = ensure_columns_exist(df, columns_needed)

    df = df.select(*[col(c) for c in columns_needed])

    # --- Normalize organization and ISP ---
    normalized_org = lower(regexp_replace(col("org"), r"[()]", ""))
    normalized_isp = lower(regexp_replace(col("isp"), r"[()]", ""))
    first_word_org = split(normalized_org, r"\s+").getItem(0)
    first_word_isp = split(normalized_isp, r"\s+").getItem(0)

    # --- Vulnerability assessment ---
    if "version" in df.columns:
        df = df.withColumn("vulnerability_assessment", vuln_assess_udf(col("version")))
    else:
        df = df.withColumn("vulnerability_assessment", lit(None))

    # --- Filtering ---
    filtered_df = df.filter(
        (col("http.status") == 200) &
        (col("product") == "Pulse Secure") &
        (
            (col("cpe23").isNull()) |
            (first_word_org != first_word_isp) |
            (col("version").isNotNull() if "version" in df.columns else lit(False))
        )
    )

    # --- Priority classification ---
    filtered_df = filtered_df.withColumn(
        "priority",
        when(col("vulnerability_assessment").startswith("likely_vulnerable"), lit(1))
        .when((col("cpe23").isNull()) & (first_word_org != first_word_isp), lit(2))
        .when((col("cpe23").isNull()) & (first_word_org == first_word_isp), lit(3))
        .otherwise(lit(4))
    )

    # --- Final optimized selection ---
    columns_to_keep = [
        "ip_str", "priority", "org", "isp", "domains",
        "version", "product",
        "country_name", "city", "CN", "O",
        "vulnerability_assessment", "timestamp"
    ]
    optimized_df = filtered_df.select(*[col(c) for c in columns_to_keep])

    return optimized_df.orderBy(col("priority").asc()), filtered_df.orderBy(col("priority").asc())
