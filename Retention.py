import json
import os

RETENTION = 4


def retention_check(pool, dom, file):

    image_list = list()
    line = dict()

    try:
        with open(pool.path + "/" + dom.get_name() + "_" + file["node"]+".log", encoding='utf-8', mode='r') as logfile:
            for jline in logfile.readlines():
                if jline == None:
                    raise EOFError
                if jline == "":
                    pass
                line = json.loads(jline)
                image_list.append(line)

            image_list = sorted(image_list, key=lambda k: k["id"])
            print("Retention kontrolu yapiliyor.")
            if len(image_list) >= RETENTION:
                base = image_list.pop(0)
                top = image_list.pop(0)
                rebase = image_list.pop(0)
                retention_delete(base, top, rebase)

    except IOError:
        print(pool.path +"/"+ dom.get_name() + "_" + file["node"]+".log")
        print(" -> log dosyasina ulasilamiyor. Dosyayi kontrol ediniz...")
    except EOFError:
        print("log dosyasi bos. full yedek alindi mi ?")
    except TypeError as e:
        print("Log dosyasinda hata var ", str(e.args))
    except Exception as e:
        print("Retention check operation failed: ")
        print(e)
        print(str(e) + "----" + str(e.args))


def retention_delete(base, top, rebase):
    print("retention: imaj temizligi yapiliyor...")
    print("base:", base)
    print("top:", top)
    print("rebase:", rebase)
    print("retention: imaj temizligi tamamlandi...")