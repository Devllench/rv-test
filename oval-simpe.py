import xml.etree.ElementTree as ET
import os
import html

class OvalToHTMLConverter:

    def __init__(self, oval_file, html_file="oval_report.html"):
        """
        Инициализация
        """
        self.oval_file = oval_file
        self.html_file = html_file
        self.root = self._parse_xml()
        self.namespace = {'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
                          'red-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
                          'ind-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent'}

    def _parse_xml(self):
        """
        Парсинг xml (oval)
        """

        try:
            tree = ET.parse(self.oval_file)
            return tree.getroot()
        except FileNotFoundError:
            print(f"Ошибка: Файл {self.oval_file} не найден.")
            return None
        except ET.ParseError as e:
            print(f"Ошибка: Ошибка парсинга XML в файле {self.oval_file}: {e}")
            return None

    def convert_to_html(self):
        """
        Преобразование в HTML
        """

        if self.root is None:
            return

        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OVAL Report</title>
            <style>
                body { font-family: sans-serif; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f2f2f2; }
                h2 { margin-top: 20px; }
                pre { background-color: #eee; padding: 10px; border: 1px solid #ccc; }
            </style>
        </head>
        <body>
            <h1>OVAL Report</h1>
        """

        definitions_element = self.root.find('.//oval:definitions', self.namespace)
        limit_count = 3
        limit = 0
        if definitions_element is not None:
            html_content += "<h2>Definitions</h2>\n"

            for definition_element in definitions_element.findall('.//oval:definition', self.namespace):
                limit = limit + 1
                if limit > limit_count:
                    break
                definition_id = definition_element.get('id')
                definition_class = definition_element.get('class')
                title_element = definition_element.find('.//oval:metadata/oval:title', self.namespace)

                title = html.escape(title_element.text) if title_element is not None and title_element.text else "N/A"
                description_element = definition_element.find('.//oval:metadata/oval:description', self.namespace)
                description = html.escape(description_element.text) if description_element is not None and description_element.text else "N/A"

                cve = definition_element.findall('.//oval:metadata/oval:advisory/oval:cve', self.namespace)
                cpe = definition_element.findall('.//oval:metadata/oval:advisory/oval:affected_cpe_list/oval:cpe', self.namespace)


                html_content += f"<h3>Definition: {title} ({definition_id})</h3>\n"
                html_content += f"<b>Class:</b> {definition_class}</p>\n"
                html_content += f"<p>{description}</p>\n"

                html_content += f"<p><b>CVE</b>:"
                for cve_element in cve:
                      html_content += f"{cve_element.text}, "
                html_content += f"<p>"


                html_content += f"<p><b>CPE:</b><p>"
                for cpe_element in cpe:
                    html_content += f"<p>{cpe_element.text}<p>"
                html_content += f"<p>"

                html_content += f"<p><b>Objects:</b>"
                for obj in set(self.get_objects_for_definition(definition_id)):
                    html_content += f"{obj}, "
                html_content += f"</p>"

                criteria_element = definition_element.find(f".//oval:criteria", self.namespace)
                html_content += f"<p><b>Criteria:</b><p>"
                if criteria_element is not None:
                    html_content += "<ul>\n"
                    for criterion_element in criteria_element.findall(".//oval:criterion", self.namespace):
                        test_ref = criterion_element.get('test_ref')
                        comment = criterion_element.get('comment')

                        if comment:
                            html_content += f"<li>{comment}</li>\n"
                            if test_ref:
                                html_content += f"<p>Test Reference: {test_ref}</p>\n"
                        elif criterion_element.get('operator'):
                            html_content += f"<li>Operator: {criterion_element.get('operator')}</li>\n"  # Добавляем логику для операторов <criterion>
                    html_content += "</ul>\n"
                else:
                    html_content += "<p>No criteria found for this definition.</p>\n"

        html_content += """
        </body>
        </html>
        """

        try:
            with open(self.html_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"OVAL файл успешно преобразован в HTML: {self.html_file}")
        except IOError as e:
            print(f"Ошибка при записи в HTML файл: {e}")

    def get_objects_for_definition(self, definition_id):
        """
        Находит объекты, связанные с определенным definition ID.
        """
        objects = []
        criteria_element = self.root.find(f".//oval:definition[@id='{definition_id}']", self.namespace)

        if criteria_element is not None:
            for criterion in criteria_element.findall('.//oval:criterion', self.namespace):
                #print(criterion.attrib)
                test_ref = criterion.get('test_ref')
                #print(test_ref)
                if test_ref:
                    #print(test_ref)
                    #test_element = self.root.find(f".//oval:red-def:rpminfo_test[@id='{test_ref}']", self.namespace)
                    test_element = self.root.find(f".//*[@id='{test_ref}']", self.namespace)
                    #print(test_element)
                    if test_element is not None:
                        try:
                            object_ref = test_element.find('.//red-def:object', self.namespace).get('object_ref')
                        except:
                            object_ref = test_element.find('.//ind-def:object', self.namespace).get('object_ref')

                        object = self.root.find(f".//*[@id='{object_ref}']", self.namespace)
                        if object is not None:
                            #print(object)
                            ob_n = None
                            if object.find('.//red-def:name', self.namespace) is not None:
                                ob_n = object.find('.//red-def:name', self.namespace).text
                            if object.find('.//ind-def:name', self.namespace) is not None:
                                ob_n = object.find('.//ind-def:name', self.namespace).text
                            if object.find('.//red-def:filepath', self.namespace) is not None:
                                ob_n = object.find('.//red-def:filepath', self.namespace).text
                            if object.find('.//ind-def:filepath', self.namespace) is not None:
                                ob_n = object.find('.//ind-def:filepath', self.namespace).text

                            #print(ob_n)
                            objects.append(ob_n)
        return objects


if __name__ == "__main__":
    # Замените на путь к вашему OVAL файлу
    oval_file_path = "rhel-8.oval.xml/rhel-8.oval.xml"
    html_file_path = "oval_report.html"

    if not os.path.exists(oval_file_path):
        print(f"Укажите валидный путь до OVAL файла: {oval_file_path}")
    else:
        converter = OvalToHTMLConverter(oval_file_path, html_file_path)
        converter.convert_to_html()