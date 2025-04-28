from pyspark.sql import SparkSession


def load_shodan_data(filepath):
    """
    Load Shodan JSON data into a Spark DataFrame.

    Args:
        filepath (str): Path to the Shodan JSON file.

    Returns:
        DataFrame: Spark DataFrame containing Shodan data.
    """
    spark = SparkSession.builder.getOrCreate()
    df = spark.read.json(filepath, multiLine=True)
    return df
