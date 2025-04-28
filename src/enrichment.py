from pyspark.sql.functions import col


def get_top_domains(filtered_df, top_n):
    """
    Get the top 3 unique domains based on the priority from the exploded DataFrame.

    Args:
        filtered_df (DataFrame): Spark DataFrame after exploding domains.

    Returns:
        list: List of top 3 unique domain names.
    """
    top_df = filtered_df.orderBy(col("priority").asc()).limit(top_n)
    domains_list = [row["domain"] for row in top_df.select("domain").distinct().collect()]
    return domains_list
