# Prisma Cloud Inspect

## Description

The `inspect.sh` script queries the Prisma Cloud API for all enabled Policies,  
and for all Alerts within a Relative Time Range (with a default of one month),
and outputs the results to `${CUSTOMER_NAME}-policies.txt` and `${CUSTOMER_NAME}-alerts.txt` files.

The `inspect.py` script parses the policies and alerts files created by the `inspect.sh` script, 
calculating various results. It's output utilizes tabs, allowing for import into a spreadsheet.

## Usage

* Download the `inspect.sh` and `inspect.py` scripts.
* Execute the `inspect.sh` script to collect the data.
* Execute the `inspect.py` script to process the data.
* Import the data into Google Sheets, and/or Google Slides (For example: [PCS Inspect](https://docs.google.com/presentation/d/10x_PGAu0ZPUGZMc4Tfevf9gpXvhIUOwGrBuRBkI6Jjc/edit?usp=sharing))
* Profit!

## Example

```
vi inspect.sh
chmod +x inspect.sh inspect.py
./inspect.sh -c example -u "https://api.prismacloud.io" -a "aaaaaaaa-1111-aaaa-1111-aaaaaaaa1111" -s "ssss1111ssss1111ssss1111="
./inspect.py -c example
./inspect.py -c example > example.tab
```

## Example Output

[example.tab](example.tab)

## To Do:

* Allow the `inspect.py` script to output directly to Google Sheets and/or Google Slides, or to a file directly importable into one or both of those formats.
