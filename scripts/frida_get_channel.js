/*
 Based on IndiHome STB HG680P with firmware version RP0113-202009072127
 Tested Frida version: 12.4.7

 */

function printChannels() {
	Java.perform(function () {
		console.log("Performing..");
		Java.choose("com.fiberhome.iptv.FHConfig", {
			onMatch: function (instance) {
				console.log("\nFound instance: " + instance);
				var userChannel = instance.mUsrchannelIdList.value;
				var iterator = userChannel.entrySet().iterator();
				var Entry = Java.use("java.util.Map$Entry");
				var entries = {};
				while (iterator.hasNext()) {
					var entry = Java.cast(iterator.next(), Entry);
					entries[entry.getKey()] = entry.getValue().toString();
					// console.log("Channel: " + entry.getKey());
					// console.log("Value: " + entry.getValue());
				}
				
				send(entries);
				return "stop";
			},

			onComplete: function () {}
		});
	});
}

printChannels();
