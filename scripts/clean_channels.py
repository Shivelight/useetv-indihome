import json

import relaxed_json


with open("channels.json") as fp:
    channels = json.load(fp)

clean_channels = {}
for k, v in channels.items():
    if int(k) > 999:
        continue
    data = relaxed_json.parse(f"{{{v.replace('=', ':')}}}")
    clean_channels[k] = data

with open("clean_channels.json", "w") as fp:
    fp.write(json.dumps(clean_channels, indent=4, sort_keys=True))

print(f"Written {len(clean_channels)} channels to clean_channels.json")
