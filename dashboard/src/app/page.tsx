"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";

export default function Home() {
  const [message, setMessage] = useState("Say hello to HackYeah in one sentence.");
  const [answer, setAnswer] = useState("");
  const [busy, setBusy] = useState(false);

  async function send() {
    setBusy(true);
    setAnswer("");
    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message }),
      });
      if (!res.ok || !res.body) {
        setAnswer(`Error ${res.status}: ${await res.text()}`);
        return;
      }
      // Stream the answer in as it arrives.
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        setAnswer((a) => a + decoder.decode(value, { stream: true }));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col gap-4 p-6">
      <h1 className="text-2xl font-semibold">HackYeah starter</h1>
      <Textarea value={message} onChange={(e) => setMessage(e.target.value)} rows={4} />
      <Button onClick={send} disabled={busy || !message.trim()}>
        {busy ? "Thinking…" : "Send"}
      </Button>
      {answer && (
        <Card>
          <CardHeader>
            <CardTitle>Answer</CardTitle>
          </CardHeader>
          <CardContent className="whitespace-pre-wrap">{answer}</CardContent>
        </Card>
      )}
    </main>
  );
}
