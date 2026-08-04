import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  listProfiles,
  loadProfile,
  profileSkeleton,
  profileTemplates,
  saveProfile,
  type SiteProfile,
} from "./site-profile.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "memparty-profiles-"));
  process.env.MEMPARTY_PROFILES = dir;
});

afterEach(() => {
  delete process.env.MEMPARTY_PROFILES;
  rmSync(dir, { recursive: true, force: true });
});

function validProfile(name: string): SiteProfile {
  return {
    name,
    site: "http://192.0.2.1:8080",
    createdAt: new Date().toISOString(),
    title: "示例站点",
    template: "<!DOCTYPE html><html><body>skin</body></html>",
    contentType: "text/html; charset=utf-8",
    paths: ["/api/", "/news/"],
  };
}

describe("profile store", () => {
  it("saves, loads and lists profiles", () => {
    saveProfile(validProfile("t1"));
    expect(listProfiles()).toEqual(["t1"]);
    const loaded = loadProfile("t1");
    expect(loaded.template).toContain("skin");
    expect(loaded.paths).toEqual(["/api/", "/news/"]);
  });

  it("rejects an invalid name", () => {
    expect(() => saveProfile(validProfile("bad/name"))).toThrow(/invalid profile name/);
  });

  it("rejects a non-HTML template", () => {
    const profile = validProfile("t2");
    profile.template = "not html";
    expect(() => saveProfile(profile)).toThrow(/must be a full HTML page/);
  });

  it("rejects a bad site origin", () => {
    const profile = validProfile("t3");
    profile.site = "not-a-url";
    expect(() => saveProfile(profile)).toThrow(/site must be an http/);
  });

  it("loadProfile validates the stored file too", () => {
    saveProfile(validProfile("t4"));
    // corrupt the stored file by hand
    const path = join(dir, "t4.json");
    const raw = JSON.parse(readFileSync(path, "utf8"));
    raw.template = "nope";
    writeFileSync(path, JSON.stringify(raw));
    expect(() => loadProfile("t4")).toThrow(/full HTML page/);
  });

  it("loadProfile explains how to fix a missing profile", () => {
    expect(() => loadProfile("nope")).toThrow(/unknown profile/);
  });

  it("profileSkeleton produces a valid, fillable profile", () => {
    const skeleton = profileSkeleton("t5", "http://192.0.2.1/");
    skeleton.templates![0]!.title = "填好的标题";
    skeleton.paths = ["/app/"];
    expect(() => saveProfile(skeleton)).not.toThrow();
    expect(loadProfile("t5").site).toBe("http://192.0.2.1");
  });

  it("accepts multiple templates and normalizes the legacy single triple", () => {
    const multi = validProfile("t6");
    multi.templates = [
      { title: "a", template: "<html><body>a</body></html>", contentType: "text/html" },
      { title: "b", template: "<html><body>b</body></html>", contentType: "text/html", weight: 3 },
    ];
    multi.template = undefined;
    expect(profileTemplates(multi)).toHaveLength(2);
    expect(() => saveProfile(multi)).not.toThrow();

    // legacy shape (no templates[], only template/title/contentType) normalizes to one
    const legacy = validProfile("t7");
    expect(profileTemplates(legacy)).toHaveLength(1);
    expect(profileTemplates(legacy)[0]!.template).toContain("skin");
  });

  it("rejects when there is no usable template at all", () => {
    const empty = validProfile("t8");
    empty.template = undefined;
    empty.templates = [];
    expect(() => saveProfile(empty)).toThrow(/at least one template/);
  });

  it("rejects a bad entry inside templates[]", () => {
    const multi = validProfile("t9");
    multi.templates = [
      { title: "ok", template: "<html><body>ok</body></html>", contentType: "text/html" },
      { title: "bad", template: "nope", contentType: "text/html" },
    ];
    expect(() => saveProfile(multi)).toThrow(/templates\[1\]\.template/);
  });

  it("accepts a valid cipher section", () => {
    const p = validProfile("c1");
    p.cipher = { algorithm: "aes-cbc", encoding: "hex", padTail: true, marker: "html-comment" };
    expect(() => saveProfile(p)).not.toThrow();
    expect(loadProfile("c1").cipher?.algorithm).toBe("aes-cbc");
  });

  it("rejects unknown cipher values", () => {
    const p = validProfile("c2");
    p.cipher = { algorithm: "rot13" as never };
    expect(() => saveProfile(p)).toThrow(/cipher\.algorithm/);

    const p2 = validProfile("c3");
    p2.cipher = { encoding: "utf16" as never };
    expect(() => saveProfile(p2)).toThrow(/cipher\.encoding/);

    const p3 = validProfile("c4");
    p3.cipher = { marker: "css" as never };
    expect(() => saveProfile(p3)).toThrow(/cipher\.marker/);

    const p4 = validProfile("c5");
    p4.cipher = { padTail: "yes" as never };
    expect(() => saveProfile(p4)).toThrow(/cipher\.padTail/);
  });

  it("accepts a non-HTML template that carries {{payload}}", () => {
    const p = validProfile("j1");
    p.templates = [
      { title: "api", template: '{"code":0,"data":"{{payload}}"}', contentType: "application/json" },
    ];
    expect(() => saveProfile(p)).not.toThrow();
  });

  it("rejects a non-HTML template without the placeholder", () => {
    const p = validProfile("j2");
    p.templates = [{ title: "api", template: '{"code":0}', contentType: "application/json" }];
    expect(() => saveProfile(p)).toThrow(/payload|full HTML page/);
  });

  it("rejects a bad bodyStyle and bad headers", () => {
    const p = validProfile("j3");
    p.request = { secretField: "t", bodyStyle: "xml" as never };
    expect(() => saveProfile(p)).toThrow(/bodyStyle/);

    const p2 = validProfile("j4");
    p2.request = { secretField: "t", headers: { Accept: 42 } as never };
    expect(() => saveProfile(p2)).toThrow(/headers/);
  });

  it("accepts a bodyTemplate carrying {{payload}} (any body format)", () => {
    const p = validProfile("bt1");
    p.request = {
      secretField: "content",
      bodyTemplate: '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"{{payload}}"}]}',
      headers: { Accept: "application/json" },
    };
    expect(() => saveProfile(p)).not.toThrow();
  });

  it("rejects a bodyTemplate without the placeholder or with secretIn!=body", () => {
    const p = validProfile("bt2");
    p.request = { secretField: "t", bodyTemplate: '{"a":"b"}' };
    expect(() => saveProfile(p)).toThrow(/bodyTemplate.*payload/);

    const p2 = validProfile("bt3");
    p2.request = { secretField: "t", secretIn: "query", bodyTemplate: "x={{payload}}" };
    expect(() => saveProfile(p2)).toThrow(/secretIn=body/);
  });
});
