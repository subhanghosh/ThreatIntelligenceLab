import requests, re, xlsxwriter

URL = "https://bazaar.abuse.ch/browse/"
page = requests.get(URL)

workbook = xlsxwriter.Workbook('SHA256_Values.xlsx')
worksheet = workbook.add_worksheet()

header_format = workbook.add_format({'bold': True, 'font_color': 'blue'})
header_format.set_font_size(14)
header_format.set_underline()
header_format.set_align('center')

row, column = 1, 0
worksheet.write(0, column, 'List of unique SHA-256 values of MalwareBazar Samples', cell_format)

sha_values = re.findall("[A-Fa-f0-9]{64}", page.text)
sha_unique = set(sha_values)

cell_format = workbook.add_format()
cell_format.set_align('center')

for item in sha_unique:
    worksheet.write(row, column, item, cell_format)
    row+=1

workbook.close()
