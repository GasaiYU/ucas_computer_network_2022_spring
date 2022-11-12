import os
import re
import matplotlib.pyplot as plt


def read_cwnd_from_txt(file_name: str):
    res = []
    time = []
    with open(file_name, "r") as f:
        for line in f.readlines():
            d = re.search("(\d+.\d+),\s", line).group(1)
            m = re.search("\scwnd:(\d+)\s", line)
            if m:
                m = m.group(1)
                res.append(int(m))
                time.append(float(d))
            
    start = time[0]
    time = [t - start for t in time]
    return res, time

def read_qlen_from_txt(file_name: str):
    time = []
    res = []
    with open(file_name, "r") as f:
        for line in f.readlines():
            line_s = re.split(",\s", line)
            if len(line_s) == 2:
                time.append(float(line_s[0]))
                res.append(int(line_s[1]))
    start = time[0]
    time = [t - start for t in time]
    return res, time


def read_rtt_from_txt(file_name: str):
    time = []
    res = []
    with open(file_name, "r") as f:
        for line in f.readlines():
            d = re.search(r"(\d+.\d+),\s", line)
            rtt = re.search(r"\stime=(\d+)\s", line)
            if rtt and d:
                rtt = rtt.group(1)
                d = d.group(1)
                res.append(float(rtt))
                time.append(float(d))
    start = time[0]
    time = [t - start for t in time]
    return res, time    


def read_iperf_from_txt(file_name: str):
    time = []
    res = []
    with open(file_name, "r") as f:
        for line in f.readlines():
            m = re.search(r"(\d+.\d+)\sMbits", line)
            if m:
                res.append(float(m.group(1)))
    time = [i * 0.5 for i in range(len(res))]
    return time, res


def plot_iperf_data():
    time1, res1 = read_iperf_from_txt(os.path.join(f"qlen-50", "iperf_result_50.txt"))
    time2, res2 = read_iperf_from_txt(os.path.join(f"qlen-100", "iper_result_100.txt"))
    time3, res3 = read_iperf_from_txt(os.path.join(f"qlen-200", "iper_result_200.txt"))
    
    # plt.plot(time1, res1, "o", label="qsize=50")
    # plt.plot(time2, res2, "o", label="qsize=100")
    plt.plot(time3, res3, "o", label="qsize=200")
    
    plt.xlabel("time")
    plt.ylabel("speed")
    
    plt.legend()
    plt.show()
    


def plot_(func_name, read_file_name):
    res1, time1 = func_name(os.path.join(f"taildrop", read_file_name))
    res2, time2 = func_name(os.path.join(f"red", read_file_name))
    res3, time3 = func_name(os.path.join(f"codel", read_file_name))
    
    plt.plot(time1, res1, "r", label="taildrop")
    plt.plot(time2, res2, "b", label="red")
    plt.plot(time3, res3, label="codel")
    
    plt.xlabel("time")
    plt.ylabel("rtt")
    plt.yscale("log")
    
    plt.legend()
    plt.show()
    

if __name__ == "__main__":
    plot_iperf_data()
        