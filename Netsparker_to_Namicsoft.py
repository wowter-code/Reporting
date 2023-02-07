import sys
import csv
import xml.etree.ElementTree as ET
import re
import pandas as pd
from html.parser import HTMLParser
import os

class TextExtractor(HTMLParser):
    def __init__(self):
        self.result = []
        self.indent_level = 0
        self.indent_string = '    '
        super().__init__()

    def handle_starttag(self, tag, attrs):
        if tag in ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li']:
            self.result.append('\n' + self.indent_string * self.indent_level)
        if tag == 'li':
            self.indent_level += 1

    def handle_endtag(self, tag):
        if tag == 'li':
            self.indent_level -= 1

    def handle_data(self, data):
        self.result.append(data)

def extract_text(html):
    extractor = TextExtractor()
    extractor.feed(html)
    return ''.join(extractor.result)


def extract_urls(html):
  # Find all URLs in the href attribute of anchor tags
  url_pattern = r'href=[\'"]?([^\'" >]+)'
  url_regex = re.compile(url_pattern)
  urls = url_regex.findall(html)

  # Format the URLs as hyperlinks with bullets
  formatted_urls = "\n".join(["{}".format(url) for url in urls])
  return formatted_urls


def exclude_rows_and_write(file_name, word1, word2, column, output_file):
    with open(file_name) as csv_file, open(output_file, 'w', newline='') as output_csv:
        csv_reader = csv.reader(csv_file, delimiter=',')
        csv_writer = csv.writer(output_csv)
        
        header = next(csv_reader)
        if column not in header:
            raise ValueError(f"{column} not found in header")
        col_index = header.index(column)

        csv_writer.writerow(header)
        
        for row in csv_reader:
            if row[col_index] not in (word1, word2):
                csv_writer.writerow(row)


# get xml file from command line argument
xml_file = sys.argv[1]

# parse xml file
tree = ET.parse(xml_file)
root = tree.getroot()

# create csv file
csv_file = open('netsparker_report.csv', 'w', newline='')
csv_writer = csv.writer(csv_file)

# write header row
csv_writer.writerow(['Plugin Name', 'Host IP', 'Severity', 'Synopsis', 'Description', 'Solution', 'See Also'])

# iterate through xml and write data to csv
for finding in root.findall("./vulnerability"):
    name = finding.find('title').text
    url = finding.find('url').text
    severity = finding.find('severity').text
    description = extract_text(finding.find('description').text).replace('Invicti Standard', 'During the testing, we')
    impact = extract_text(finding.find('impact').text)
    remedy = extract_text(finding.find('remedy').text)
    externalReferences = extract_urls(finding.find('externalReferences').text)
    csv_writer.writerow([name, url, severity, description, impact, remedy, externalReferences])

# close csv file
csv_file.close()

exclude_rows_and_write("netsparker_report.csv", "Information", "BestPractice", "Severity", "filtered_netsparker_report.csv")

# Read the CSV file
df = pd.read_csv("filtered_netsparker_report.csv")

# Convert the CSV file to an Excel file
df.to_excel("filtered_netsparker_report.xlsx", index=False)

#Cleanup
os.remove("netsparker_report.csv")
os.remove("filtered_netsparker_report.csv")