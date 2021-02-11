# Prisma Cloud Inspection Script

## Description

The `pcs-inspect.py` script queries the Prisma Cloud API for all enabled Policies
and for all Alerts within a Relative Time Range (with a default of one month),
and outputs the results to CSV files. It can process those files, outputting:

* Alerts By Compliance Standard
* Alerts By Policy
* Alerts Totals

It's output utilizes tabs, allowing for import into a spreadsheet.

### Usage

* Download the `pcs-inspect.py` script.
* Execute `pcs-inspect.py` to collect and process the data.
* Import the data into Google Sheets, and/or Google Slides ( for example: [PCS Inspect Report](https://docs.google.com/presentation/d/10x_PGAu0ZPUGZMc4Tfevf9gpXvhIUOwGrBuRBkI6Jjc/edit?usp=sharing) )
* Profit!

(You can independently execute the collect and process steps of the script by specifying `-m collect` or `-m process`)

Use `./pcs-inspect.py -h` for a complete list of parameters.

Note that collection requires a Prisma Cloud Access Key with `ACCOUNT GROUP READ ONLY` privileges configured for all accounts, or `SYSTEM ADMIN` privileges.

### Example

```
chmod +x pcs-inspect.py

./pcs-inspect.py --customer_name example -u "https://api.prismacloud.io" -a "aaaaaaaa-1111-aaaa-1111-aaaaaaaa1111" -s "ssss1111ssss1111ssss1111="
```

See [example.tab](example.tab) for example output.
