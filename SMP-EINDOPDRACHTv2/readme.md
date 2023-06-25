# Network Analyzer

This network analyzer is a Python script that allows you to perform various analyses on a network dataset. It provides three analysis options: most requests scan, amount of hosts scan, and SYN flood scan. The script takes a dataset file as input and produces relevant information based on the chosen analysis options.

## Instructions

To use the network analyzer, follow the steps below:

1. Clone or download the repository to your local machine.

2. Prepare your dataset file in JSON format. Make sure the file is accessible and contains the necessary network data for analysis.

3. Run the network analyzer script with the desired options. Use the following command-line arguments:

- python network_analyzer.py -ds <dataset_file> [options]


Replace `<dataset_file>` with the path to your dataset file.

Available options:
- `-mr, --most-requests`: Perform analysis of most requests.
- `-aoh, --amount-of-hosts`: Perform analysis of the amount of hosts.
- `-uni <university_network_ip>`: Specify the university network IP address for the amount of hosts analysis.
- `-ss, --synflood-scan`: Perform analysis of SYN flood scan.

You can choose one or more options to run multiple analyses simultaneously.

5. The network analyzer will process the dataset and display the results based on the selected options.

## Examples

1. Perform the most requests analysis:

- python network_analyzer.py -ds dataset.json -mr

2. Perform the amount of hosts analysis for a university network:

- python network_analyzer.py -ds dataset.json -aoh -uni 192.168.0.1

3. Perform the SYN flood scan analysis:

- python network_analyzer.py -ds dataset.json -ss

## Map Structure

SMP-EINDOPDRACHT:.
│   readme.md
│
├───docs
│       documentation.md
│       subquestions.md
│
├───smpnc
│       networkanalyzer.py
│       smpdataset.json
│
└───tests
        negative_most_requests_test.py
        positive_most_requests_test.py
        __init__.py


## License

This network analyzer is released under the MIT License.

Feel free to adjust the wording as needed for your specific context.

Let me know if there's anything else I can assist you with!

