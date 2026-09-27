# Python Security Log Analysis

This is the type of learning that i introduced in my early python studying which expanded to more complicated apps later on and very soon gonna dive deeper into ML.

A small data-analysis project showing the same security-log problem solved in two stages:

1. **Core Python** — lists, dictionaries, loops, functions, JSON, file I/O and basic aggregation.
2. **Pandas + NumPy + Matplotlib** — DataFrames, filtering, grouping, numerical operations and visualisation.

The purpose of the project is to document my progression from core Python data handling into the libraries commonly used for data analysis and machine-learning preparation.

## What the project analyses

The sample dataset contains login records with:

- source IP address
- username
- login status
- number of attempts
- country

Both implementations calculate:

- total records
- successful and failed records
- total and average login attempts
- attempts grouped by user and IP
- suspicious failed-login records

The library version additionally demonstrates NumPy statistics, Pandas DataFrames and a Matplotlib chart.

## Repository structure

```text
Python-Security-Log-Analysis/
├── core_python/
│   ├── security_log_analysis.py
│   └── security_log_analysis.ipynb
├── pandas_numpy_matplotlib/
│   ├── security_log_analysis.py
│   └── security_log_analysis.ipynb
├── data/
│   └── security_logs.json
├── outputs/
├── .gitignore
├── requirements.txt
└── README.md
```

## Version 1 — Core Python

This implementation deliberately avoids third-party data-analysis libraries.

Concepts demonstrated:

- `json`
- `with open(...)`
- read / write / append modes
- lists and dictionaries
- loops and conditions
- functions
- dictionary aggregation
- file output
- simple security-alert logic

Run it with:

```bash
python core_python/security_log_analysis.py
```

## Version 2 — Pandas, NumPy and Matplotlib

This implementation solves the same problem using common data-analysis libraries.

Concepts demonstrated:

- `pandas.read_json`
- DataFrames
- boolean filtering
- `groupby`
- sorting and aggregation
- conversion to NumPy arrays
- `np.sum`, `np.mean`, `np.max`, `np.median`
- Matplotlib bar charts
- CSV and JSON export

Install dependencies:

```bash
pip install -r requirements.txt
```

Run it with:

```bash
python pandas_numpy_matplotlib/security_log_analysis.py
```

## Why I built both versions

I wanted to understand what the libraries are doing for me rather than learning only library syntax. The core-Python version makes the underlying iteration, filtering and aggregation explicit. The Pandas/NumPy version shows how the same operations become more concise and scalable when working with structured data.

This is a learning project rather than a production security system. The dataset is synthetic and the suspicious-login rule is intentionally simple.

## What I learned

The biggest lesson was that data analysis is still built on the same programming fundamentals: input, data structures, conditions, transformations and output. Libraries such as Pandas make those operations more efficient and expressive, but understanding the core Python version makes the higher-level version easier to reason about.

## Next steps

- larger CSV/JSON datasets
- timestamp-based analysis
- missing-data handling
- feature engineering
- additional visualisations
- basic anomaly detection
- supervised-learning experiments
