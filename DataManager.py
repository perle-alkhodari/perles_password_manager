

class DataManager:

    @staticmethod
    def serialize(service_name, username, password, delimiter, new_liner):
        serialized_data = service_name + delimiter + username + delimiter + password + new_liner
        return serialized_data

    @staticmethod
    def deserialize(data, delimiter, new_liner):
        deserialized_data = [line.split(delimiter) for line in data.split(new_liner)]
        return deserialized_data

    @staticmethod
    def create_file(filename, data):
        with open(filename, "w") as file:
            file.write(data)

    @staticmethod
    def overwrite_file(filename, data):
        with open(filename, "w") as file:
            file.write(data)

    @staticmethod
    def extract_from_file(filename):
        with open(filename, "r") as file:
            data = file.read()

        return data

    @staticmethod
    def li_of_li_to_li_to_tup(li_of_li):
        return [tuple(li) for li in li_of_li]
