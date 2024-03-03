// Example radius client sending auth packets.
const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

var radius = require("../lib/radius");
var dgram = require("dgram");
var util = require("util");

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});

app.post("/login", async (req, res) => {
  var secret = req.body.secret;
  var username = req.body.username;

  var packet_accepted = {
    code: "Access-Request",
    secret: secret,
    identifier: 0,
    attributes: [
      ["NAS-IP-Address", "10.5.5.5"],
      ["User-Name", username],
      ["User-Password", "123"],
    ],
  };

  // var packet_rejected = {
  //   code: "Access-Request",
  //   secret: secret,
  //   identifier: 1,
  //   attributes: [
  //     ["NAS-IP-Address", "10.5.5.5"],
  //     ["User-Name", "egarak"],
  //     ["User-Password", "tailoredfit"],
  //   ],
  // };

  // var packet_wrong_secret = {
  //   code: "Access-Request",
  //   secret: "wrong_secret",
  //   identifier: 2,
  //   attributes: [
  //     ["NAS-IP-Address", "10.5.5.5"],
  //     ["User-Name", "riker"],
  //     ["User-Password", "Riker-Omega-3"],
  //   ],
  // };

  var client = dgram.createSocket("udp4");

  client.bind(49001);

  var response_count = 0;

  client.on("message", function (msg, rinfo) {
    var response = radius.decode({ packet: msg, secret: secret });
    var request = sent_packets[response.identifier];

    // although it's a slight hassle to keep track of packets, it's a good idea to verify
    // responses to make sure you are talking to a server with the same shared secret
    var valid_response = radius.verify_response({
      response: msg,
      request: request.raw_packet,
      secret: request.secret,
    });
    if (valid_response) {
      res.send(
        "Got valid response " +
          response.code +
          " for packet id " +
          response.identifier
      );
      console.log(
        "Got valid response " +
          response.code +
          " for packet id " +
          response.identifier
      );
      // take some action based on response.code
    } else {
      console.log(
        "WARNING: Got invalid response " +
          response.code +
          " for packet id " +
          response.identifier
      );
      // don't take action since server cannot be trusted (but maybe alert user that shared secret may be incorrect)
    }

    if (++response_count == 3) {
      client.close();
    }
  });

  var sent_packets = {};
  //packet_wrong_secret
  // packet_rejected
  [packet_accepted].forEach(function (packet) {
    var encoded = radius.encode(packet);
    sent_packets[packet.identifier] = {
      raw_packet: encoded,
      secret: packet.secret,
    };
    client.send(encoded, 0, encoded.length, 1812, "localhost");
    // client.send(encoded, 0, encoded.length, 1812, "nettdep1.onrender.com");
  });
});

const port = process.env.port;
app.listen(port || 3001, function (err) {
  if (err) {
    console.log(err);
  } else {
    console.log("Client server is running on port 3001");
  }
});
