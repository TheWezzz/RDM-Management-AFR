import datetime
import re
from typing import Union

rdm_uid = str
timestamp = datetime.datetime
manufacturer = str
device_name = str
firmware_version = str
sensors = {str: Union[int, float, str]}
errors = set[str]
lamp_hours = int
serial_number = str
extra_param = dict

device_record = {str: Union[str, int, sensors, errors, extra_param]}
device_records = {timestamp: device_record}
log = {rdm_uid: device_records}

# ERRORS AND WARNINGS
err_warn = str
# formatting functions
ERR_WRONG_DATE_TO_UNIX_CONVERSION = 'could not convert datetime to unix format, datetime class returned this error:'
ERR_WRONG_UID_FORMAT = "incorrect rdm_uid format, must be xxxx-xxxxxxxx"
ERR_WRONG_DATETIME_FORMAT = 'incorrect datetime format, must be 2yyy-mm-dd hh:mm:ss and >2000'
ERR_UNKNOWN = "unknown error"
# add log function
WARN_EXISTING_UID_TIME_COMBO = "rdm_uid with given timestamp already existed, skipped"
# getter functions
ERR_NO_RDM_UID = "could not find matching id"
WARN_ONLY_ONE_RECORD = "only one record found, make sure this is a new uid"
INFO_SUCCESS = "success"
ERR_NO_NAMES_FOUND = "could not find any name"
ERR_NO_FW_FOUND = "could not find any firmware version"
ERR_INCOMPLETE_FW_HISTORY = "missing firmware versions at some timestamps"
ERR_MISSING_FW = "missing firmware version"

month_texts = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
               "november", "december")

def str_to_hex(s: str) -> str:
    """
    Convert message hex byte representation.
    """
    s_bytes = s.encode('ascii', 'replace')
    return s_bytes.hex()

def str_to_html(s: str) -> str:
    return s.replace("\n", "<br>")

def param_to_string(parameters: dict,
                    prefix: str = "",
                    indent: str = "  ",
                    endl: str = "\n") -> str:
    s = parameters.get('sensors', [])
    e = parameters.get('errors', [])

    res = (endl +
           f"{prefix}Manufacturer: "    + parameters.get("manufacturer", "unknown") + endl +
           f"{prefix}Name: "            + parameters.get("name", "unknown") + endl +
           f"{prefix}Firmware version: "+ parameters.get("firmware_version", "unknown") + endl +
           f"{prefix}Sensors:"          + endl)
    for sensor in s:
        res += prefix + indent          + f"{sensor}: {s[sensor]}{endl}"
    res += f"{prefix}Errors:"           + endl
    for error in e:
        res += prefix + indent          + error + endl
    res += (
            f"{prefix}Lamp hours: "     + str(parameters.get('lamp_hours', 'unknown')) + endl)
    return res


def datetime_to_unix(t: timestamp) -> tuple[float, err_warn]:
    try:
        return t.timestamp(), ""
    except Exception as e:
        return (0,
                ERR_WRONG_DATE_TO_UNIX_CONVERSION + '\n' +
                str(e))


def check_uid_and_datetime_format(uid: str, time: str) -> err_warn:
    uid_pattern = '\w{4}-\w{8}' # TODO check met de lijst van RDM manufacturers of hij geldig is
    time_pattern = '\A2\d{3} - [1-12] - [1-31]: [0-1][0-9]|2[0-3]:[0-5][0-9]:[0-5][0-9]\Z'
    uid_found = re.search(uid_pattern, uid)
    time_found = re.search(time_pattern, time)

    if uid_found and time_found:
        return ''
    elif not uid_found:
        return ERR_WRONG_UID_FORMAT
    elif not time_found:
        return ERR_WRONG_DATETIME_FORMAT
    else:
        return ERR_UNKNOWN


class RDM_logs:
    def add_data(
            self,
            uid: rdm_uid,
            time: datetime.datetime,
            mftr: manufacturer,
            name: device_name,
            fw_vs: firmware_version,
            sens: sensors,
            err: list[str],
            hours: lamp_hours,
            **kwargs) -> err_warn | bool:
        if uid in self.data:
            if time in self.data[uid]:
                return f"WARNING: uid {uid} with timestamp {time}: {WARN_EXISTING_UID_TIME_COMBO}"
            else:
                self.data[uid].update({time: {
                    'manufacturer': mftr,
                    'name': name,
                    'firmware_version': fw_vs,
                    'sensors': sens,
                    'errors': set(err),
                    'lamp_hours': hours,
                    **kwargs}})  # Mogelijkheid om extra parameters toe te voegen
                return True
        else:  # uid not in log
            self.data.update({uid: {time: {
                    'manufacturer': mftr,
                    'name': name,
                    'firmware_version': fw_vs,
                    'sensors': sens,
                    'errors': set(err),
                    'lamp_hours': hours,
                    **kwargs}}})
            return True

    def read_file(self):  # TODO: finish this.
        with open(self.data_log_location, 'r') as f:
            for line in f:
                l = line.split("; ")
                check_uid_and_datetime_format(l[0], l[1])

    def write_to_file(self):  # TODO: implement loop through self.log and write to file
        with open(self.data_log_location, 'w') as csvfile:
            for uid in self.get_all_rdm_uids():
                for time in self.data[uid]:
                    line = "; ".join([uid, str(time)])
                    for param in self.data[uid][time].values():
                        line += "; " + str(param)
                    line += "\n"
                    csvfile.write(line)

    def __init__(self, database_location: str):

        self.selected_uid = rdm_uid
        self.selected_name = device_name
        self.data_log_location = database_location
        self.data = {
            '0000:0000': {
                datetime.datetime(1900, 1, 1,
                                  9, 00, 00): {
                    'manufacturer': 'TEST',
                    'name': 'Dummy model',
                    'firmware_version': 'v1.0',
                    'sensors': {
                        'voltage': 230,
                        'temperature': 80},
                    'errors': {},
                    'lamp_hours': 2000,
                    'serial_number': '0000'},
            }
        }

    def get_device_records(self, uid: rdm_uid) -> tuple[device_records, err_warn]:
        records = self.data.get(uid, None)
        if records:
            if len(records.values()) == 1:
                return records, WARN_ONLY_ONE_RECORD
            keylist = list(records.keys())
            keylist.sort()
            sorted_device_records = {key: records[key] for key in keylist}
            return sorted_device_records, INFO_SUCCESS
        else:
            raise ValueError(f"UID '{uid}': {ERR_NO_RDM_UID}")

    def get_latest_record(self, uid: rdm_uid) -> tuple[timestamp, device_record, None] | tuple[None, None, err_warn]:
        rec, err = self.get_device_records(uid)
        if rec:
            latest_timestamp = max(rec.keys())
            return latest_timestamp, rec[latest_timestamp], err
        else:
            return None, None, err

    def get_all_rdm_uids(self):
        return list(self.data.keys())

    def get_devices_by_manufacturer(self, mftr: manufacturer):
        pass

    def get_name(self, uid: rdm_uid) -> tuple[device_name, err_warn]:
        rec, get_rec_text = self.get_device_records(uid)
        if rec:
            rec_count = len(rec)
            name_count = 0
            name = None

            for parameters in rec.values():
                name = parameters.get('name', None)
                if not name:
                    continue
                else:
                    name_count += 1

            if not name:
                raise ValueError(f"retrieved {rec_count} records from uid {uid}: {get_rec_text}. {ERR_NO_NAMES_FOUND}. ")
            elif name_count != rec_count:
                raise ValueError(f"retrieved {rec_count} records from uid {uid}: {get_rec_text}. only {name_count} names found. ")
            else:
                return name

        else:
            raise ValueError(f"could not retrieve record from uid {uid}: {get_rec_text}. ")

    def get_names(self, uids: list[rdm_uid]) -> list[device_name]:
        res = []
        err_list = []
        for uid in uids:
            try:
                name= self.get_name(uid)
            except ValueError as e:
                err_list.append(e)
            else:
                res.append(name)
        if err_list:
            raise ExceptionGroup("found records with invalid names.", err_list)
        return res

    def get_fw(self, uid: rdm_uid) -> serial_number:
        rec, get_rec_text = self.get_device_records(uid)
        if rec:
            rec_count = len(rec)
            fw_count = 0
            fw_change_count = 0
            err_list = []

            first_rec_key = list(rec.keys())[0]
            fw_version = rec[first_rec_key].get('firmware_version', None)
            for timestamp in rec:
                next_fw_version = rec[timestamp].get('firmware_version', None)
                if not next_fw_version:
                    err_list.append(ValueError(f"uid {uid} at {timestamp}: {ERR_MISSING_FW}"))
                elif next_fw_version != fw_version:
                    fw_version = next_fw_version
                    fw_count += 1
                    fw_change_count += 1
                elif fw_version == next_fw_version:
                    fw_count += 1

            if not fw_version:
                raise ExceptionGroup(f"retrieved {rec_count} records from uid {uid}: {get_rec_text}. {ERR_NO_FW_FOUND}.",
                                     err_list)
            elif fw_count < rec_count:
                raise ExceptionGroup(f"retrieved {rec_count} records from uid {uid}: {get_rec_text}. {ERR_INCOMPLETE_FW_HISTORY}.",
                                     err_list)
            else:
                return fw_version
        else:
            raise ValueError(f"could not retrieve record from uid {uid}: {get_rec_text}. ")

    def get_fws(self, uids: list[rdm_uid]) -> list[serial_number]:
        res = []
        err_list = []
        for uid in uids:
            try:
                fw = self.get_fw(uid)
            except ExceptionGroup as eGroup:
                err_list.append(eGroup)
            except ValueError as e:
                err_list.append([e])
            else:
                res.append(fw)
        if err_list:
            raise ExceptionGroup("found records with invalid firmware history", err_list)
        return res

    # TODO: go through the firmware records of a uid list and return dict
    def compare_firmware(self, uid: rdm_uid) -> tuple[bool, err_warn]:
        pass

    def device_records_to_string(self, uids: list[rdm_uid]):
        res = "\n"
        for uid in uids:
            res += f"{uid}:\n"
            rec, err = self.get_device_records(uid)
            if rec:
                for timestamp in rec:
                    print(timestamp)
                    res += (f"    "
                            f"{timestamp.day}-{month_texts[timestamp.month - 1]}, {timestamp.time()}:"
                            f"{param_to_string(rec[timestamp], "        ")}\n")
            else:
                res += "nothing to show"
        return res
