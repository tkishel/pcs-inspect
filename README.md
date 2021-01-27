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

# Prisma Cloud Usage Delta Script

## Description

The `pc-usage-delta.py` script queries the Prisma Cloud API for License/Usage data,
saving the data to a historical file, calculating the mean of the historical data,
and comparing that mean to the current usage. 
If the current usage exceeds the mean usage by a (configurable) percentage,
it will output a notification.

This is valuable for detecting a drop or spike in usage,
such as when a cloud account is onboarded or offboarded,
or the number of resources/workloads changes unexpectedly.

### Usage

* Download the `pc-usage-delta.py` script.
* Customize the `notify` function in the script to meet your notification requirements.
* Execute `pc-usage-delta.py` in the context of a cron job (TODO: or a serverless function).
* Profit!

Use `./pc-usage-delta.py -h` for a complete list of parameters.

Note that this script requires a Prisma Cloud Access Key with `ACCOUNT GROUP READ ONLY` privileges configured for all accounts, or `SYSTEM ADMIN` privileges.

### Example

```
chmod +x pc-usage-delta.py

./pc-usage-delta.py -u "https://api.prismacloud.io" -a "aaaaaaaa-1111-aaaa-1111-aaaaaaaa1111" -s "ssss1111ssss1111ssss1111="

Generating Prisma Cloud API Token
Querying Cloud Accounts
Querying Usage for 150 Cloud Accounts
......................................................................................................................................................
Current (Licensable) Resource Count: 515

Historical (Licensable) Resource Count:

{'Date': '2021-01-26', 'Resources': '1'}
{'Date': '2021-01-27', 'Resources': '104'}

NOTIFY: Spike !!!
NOTIFY: Current resource count (515) is 800 percent greater that the mean resource count (52).
NOTIFY: This notification is triggered by a delta greater than 10 percent, measured over (2) samples.
```