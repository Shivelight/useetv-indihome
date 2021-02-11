import frida
import json

session = frida.get_usb_device().attach("com.fiberhome.iptv")
script = session.create_script(open("frida_get_channel.js").read())


def on_message(message, data):
    channels = open("channels.json", "w")
    channels.write(json.dumps(message['payload'], indent=4, sort_keys=True))


script.on("message", on_message)
script.load()
