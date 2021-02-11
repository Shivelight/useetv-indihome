from collections import OrderedDict
import json


with open("clean_channels.json") as fp:
    data = json.load(fp)
    channels = OrderedDict(sorted(data.items(), key=lambda x: int(x[0])))

playlist_template = "\n#EXTINF:0,{name}\n{url}\n"

with open("useetv-indihome.m3u", "w") as fp:
    fp.write("#EXTM3U\n")
    fp.write("# Generated")
    for k, v in channels.items():
        if not v['ChannelURL'].startswith("igmp://"):
            continue
        name = f"[{k}] {v['ChannelName']}"
        url = v['ChannelURL'].replace("igmp://", "rtp://")
        fp.write(playlist_template.format(name=name, url=url))

print(len(channels))
