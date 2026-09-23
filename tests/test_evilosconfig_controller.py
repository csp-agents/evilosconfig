import base64
import importlib.util
import pathlib
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "evilosconfig_controller", ROOT / "evilosconfig-controller.py"
)
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


def message(data, *, attributes=None, publish_time=None):
    result = {"data": base64.b64encode(data).decode()}
    if attributes:
        result["attributes"] = attributes
    if publish_time:
        result["publishTime"] = publish_time
    return result


class DecodePubSubOutputTest(unittest.TestCase):
    def test_decodes_utf8(self):
        output, encoding = controller.decode_pubsub_output(
            message("dev3\\admin\r\n".encode())
        )
        self.assertEqual(output, "dev3\\admin\r\n")
        self.assertEqual(encoding, "utf-8")

    def test_auto_detects_legacy_cp949(self):
        expected = "C 드라이브의 볼륨에는 이름이 없습니다.\r\n"
        output, encoding = controller.decode_pubsub_output(
            message(expected.encode("cp949"))
        )
        self.assertEqual(output, expected)
        self.assertEqual(encoding, "cp949")

    def test_uses_agent_encoding_attribute(self):
        expected = "오후 디렉터리\r\n"
        output, encoding = controller.decode_pubsub_output(
            message(expected.encode("cp949"), attributes={"encoding": "cp949"})
        )
        self.assertEqual(output, expected)
        self.assertEqual(encoding, "cp949")

    def test_rejects_invalid_base64(self):
        with self.assertRaisesRegex(ValueError, "invalid Pub/Sub output data"):
            controller.decode_pubsub_output({"data": "not base64!"})


class PubSubProtocolTest(unittest.TestCase):
    def test_configures_up_and_down_history(self):
        fake_readline = mock.Mock()
        with mock.patch.object(controller, "console_readline", fake_readline):
            enabled = controller.configure_pubsub_console_history()

        self.assertTrue(enabled)
        self.assertEqual(
            fake_readline.parse_and_bind.call_args_list,
            [
                mock.call('"\\e[A": previous-history'),
                mock.call('"\\e[B": next-history'),
            ],
        )

    def test_console_history_gracefully_degrades_without_readline(self):
        with mock.patch.object(controller, "console_readline", None):
            self.assertFalse(controller.configure_pubsub_console_history())

    def test_publish_includes_request_id(self):
        with mock.patch.object(
            controller,
            "_pubsub_post_json",
            return_value={"messageIds": ["message-1"]},
        ) as post:
            message_id = controller.pubsub_publish(
                "project",
                "topic",
                "whoami",
                "token",
                attributes={"request_id": "request-1"},
            )

        self.assertEqual(message_id, "message-1")
        body = post.call_args.args[2]
        self.assertEqual(body["messages"][0]["attributes"]["request_id"], "request-1")
        self.assertEqual(
            base64.b64decode(body["messages"][0]["data"]), b"whoami"
        )

    def test_pull_decodes_before_acknowledging(self):
        expected = "C 드라이브\r\n"
        received = {
            "receivedMessages": [
                {
                    "ackId": "ack-1",
                    "message": message(
                        expected.encode("cp949"),
                        attributes={
                            "request_id": "request-1",
                            "encoding": "cp949",
                        },
                    ),
                }
            ]
        }
        calls = []

        def post(url, token, body, timeout):
            calls.append((url, body, timeout))
            if url.endswith(":pull"):
                return received
            if url.endswith(":acknowledge"):
                return {}
            self.fail(f"unexpected Pub/Sub call: {url}")

        with mock.patch.object(controller, "_pubsub_post_json", side_effect=post):
            output = controller.pubsub_pull(
                "project",
                "subscription",
                "token",
                timeout=1,
                request_id="request-1",
                published_after=datetime.now(timezone.utc),
            )

        self.assertEqual(output, [expected])
        self.assertTrue(calls[0][0].endswith(":pull"))
        self.assertTrue(calls[1][0].endswith(":acknowledge"))
        self.assertEqual(calls[1][1], {"ackIds": ["ack-1"]})
        self.assertGreater(calls[0][2], 10)

    def test_classifies_legacy_backlog_as_stale(self):
        command_time = datetime.now(timezone.utc)
        old_time = (command_time - timedelta(minutes=1)).isoformat().replace(
            "+00:00", "Z"
        )
        classification = controller._classify_pubsub_output(
            message(b"old", publish_time=old_time),
            "request-1",
            command_time,
        )
        self.assertEqual(classification, "stale")

    def test_nacks_another_requests_output(self):
        classification = controller._classify_pubsub_output(
            message(b"other", attributes={"request_id": "request-2"}),
            "request-1",
            datetime.now(timezone.utc),
        )
        self.assertEqual(classification, "other")


if __name__ == "__main__":
    unittest.main()
