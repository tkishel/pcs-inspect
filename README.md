# Prisma Cloud Inspection Script

## Description

The `pc-inspect.py` script queries the Prisma Cloud API for all enabled Policies
and for all Alerts within a Relative Time Range (with a default of one month),
and outputs the results to `*-policies.txt` and `*-alerts.txt` files.
It can process those files, outputting:

* Open and Closed Alerts By Compliance Standard
* Open and Closed Alerts By Policy
* Summary of Open and Closed Alerts Totals

It's output utilizes tabs, allowing for import into a spreadsheet.

### Usage

* Download the `pc-inspect.py` script.
* Execute `pc-inspect.py --mode collect` to collect the data.
* Execute `pc-inspect.py --mode process` to process the data.
* Import the data into Google Sheets, and/or Google Slides ( for example: [PCS Inspect Report](https://docs.google.com/presentation/d/10x_PGAu0ZPUGZMc4Tfevf9gpXvhIUOwGrBuRBkI6Jjc/edit?usp=sharing) )
* Profit!

Use `./pc-inspect.py -h` for a complete list of parameters.

Note that collection requires a Prisma Cloud Access Key with `ACCOUNT GROUP READ ONLY` privileges configured for all accounts, or `SYSTEM ADMIN` privileges.

### Example

```
chmod +x pc-inspect.py

./pc-inspect.py --customer_name example -u "https://api.prismacloud.io" -a "aaaaaaaa-1111-aaaa-1111-aaaaaaaa1111" -s "ssss1111ssss1111ssss1111=" -m collect

./pc-inspect.py --customer_name example -m process

./pc-inspect.py --customer_name example -m process > example.tab
```

See [example.tab](example.tab) for example output.
