from pyspark.sql.functions import col


def get_top3_domains(filtered_df):
    """
    Get the top 3 domains based on the priority from the filtered DataFrame.

    Args:
        filtered_df (DataFrame): Spark DataFrame after processing.

    Returns:
        list: List of top 3 domain names.
    """
    top3_df = filtered_df.limit(3)
    top3_df = top3_df.withColumn("domain", col("domains").getItem(0))
    domains_list = [row["domain"] for row in top3_df.select("domain").distinct().collect()]
    return domains_list
