import datetime
import random

from data import RDM_logs


def create_dummy_data():
    dummy_data = RDM_logs("C:/Users/Wesley/PycharmProjects/RDM Management/Database")
    # Creëer de centrale RDM_logs instantie

    # BMFL
    dummy_data.add_data(uid='0123:ROBE', time=datetime.datetime(2021, 10, 29,
                                                                20, 00, 00), mftr='Robe', name='BMFL',
                        fw_vs='v1.0', sens={'temperature': 30, 'humidity': 50}, err=[""],
                        hours=100, serial='SN123AB')
    # Terugkerende BMFL met andere IP en random timestamp
    for i in range(1, 100):
        dummy_data.add_data(uid='0123:ROBE', time=(datetime.datetime(2022, 1, 1,
                                                                     random.randint(0, 23), 00, 00) +
                                                   datetime.timedelta(days=20 * i + random.randint(-10, 10))
                                                   ),
                            mftr='Robe', name='BMFL', fw_vs='v1.1',
                            sens={'voltage': 230, 'temperature': 31 + random.randint(1, 50)}, err=[""],
                            hours=130 + 10 * i + random.randint(-5, 5), serial='SN123AB')

    # MegaPointe___________________________________________________________________________________________
    dummy_data.add_data(uid='89AB:CDEG', time=datetime.datetime(2025, 4, 3,
                                                                20, 00, 00),
                        mftr='Robe', name='Megapointe', fw_vs='v1.1',
                        sens={'voltage': 230, 'temperature': 31}, err=['overvoltage'], hours=200, serial='SN67890')

    for i in range(1, 20):
        dummy_data.add_data(uid='89AB:CDEG', time=datetime.datetime(2023, 5, i + random.randint(1, 3),
                                                                    20, 00, 00),
                            mftr='Robe', name='Megapointe', fw_vs='v1.1',
                            sens={'voltage': 230, 'temperature': 31 + random.randint(1, 50)}, err=[""],
                            hours=240 + i * 30 + random.randint(-15, 15), serial='SN67890')

    for i in range(1, 5000):
        sn = random.randint(1, 10)
        dummy_data.add_data(uid=f'89AB:CDEF-{sn}', time=(datetime.datetime(2022, 1, 1,
                                                                           random.randint(0, 23), 00, 00) +
                                                         datetime.timedelta(days=i * 4 + random.randint(-2, 2))),
                            mftr='Robe', name='Megapointe', fw_vs='v1.11',
                            sens={'temperature': 52 + random.randint(1, 30), 'humidity': 80, 'voltage': 230}, err=[""],
                            hours=57 + i * 20 + random.randint(-8, 8), serial=f'SN67890-{sn}')
    # Color Strike m_____________________________________________________________________________________________
    dummy_data.add_data(uid='0123:4568', time=datetime.datetime(225, 5, 4,
                                                                20, 00, 00),
                        mftr='Chauvet', name='Color Strike m', fw_vs='v5.10.4',
                        sens={'temperature': 52, 'humidity': 80}, err=[""],
                        hours=57, serial='SN123457')
    # Terugkerende Color Strike m met andere IP en latere timestamp
    for i in range(1, 5000):
        sn = random.randint(1, 10)
        dummy_data.add_data(uid=f'0123:4568-{sn}', time=(datetime.datetime(2022, 1, 1,
                                                                           random.randint(0, 23), 00, 00) +
                                                         datetime.timedelta(days=20 * i + random.randint(-10, 10))
                                                         ),
                            mftr='Chauvet', name='Color Strike m', fw_vs='v5.10.4',
                            sens={'temperature': 52, 'humidity': 80}, err=[""],
                            hours=57 + i * 10 + random.randint(-5, 5), serial=f'SN123457-{sn}')

    # Ayrton Eurus______________________________________________________________________________________________
    for i in range(1, 5000):
        sn = random.randint(1, 20)
        dummy_data.add_data(uid=f'AYRT:12-{sn}', time=(
                datetime.datetime(2022, 1, 1,
                                  random.randint(0, 23), 00, 00) +
                datetime.timedelta(days=i)),
                            mftr='Ayrton', name='Eurus Profile', fw_vs='v10.13.0.6',
                            sens={'base-temperature': 30, 'lamp-temperature': 55 + random.randint(-10, 10),
                                  'voltage': 235, 'humidity': 61, }, err=[""],
                            hours=57 + i * 10 + random.randint(-5, 5), serial=f'SN98765-{sn}')

    # Dimmers___________________________________________________________________________________________________
    for i in range(1, 10):
        dummy_data.add_data(uid=f'DIM:456{i}', time=datetime.datetime(2025, 5, 15,
                                                                      20, 00 + i, 00),
                            mftr='Elation', name=f'Fixture {i}', fw_vs='v5.10.4',
                            sens={'temperature': 22 + i * random.randint(1, 5), 'humidity': 25 + random.randint(0, 75)},
                            err=[""], hours=80 + random.randint(-50, 500), serial='SN12345')
    dummy_data.add_data(uid='Last:uid00', time=datetime.datetime(9026, 5, 7,
                                                                 20, 00, 00),
                        mftr='Chauvet', name='Fixture A', fw_vs='v1.1',
                        sens={'temperature': 25, 'humidity': 60}, err=['Tilt motor'], hours=3435, serial='SN12345')

    # Voeg hier eventueel meer dummy data toe

    return dummy_data
