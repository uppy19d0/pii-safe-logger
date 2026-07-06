import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

function git(args) {
  return execFileSync("git", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();
}

function tryGit(args) {
  try {
    return git(args);
  } catch {
    return "";
  }
}

function parseVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(version);

  if (!match) {
    throw new Error(`Invalid SemVer version: ${version}`);
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3])
  };
}

function compareVersions(current, previous) {
  const currentParts = parseVersion(current);
  const previousParts = parseVersion(previous);

  for (const part of ["major", "minor", "patch"]) {
    if (currentParts[part] > previousParts[part]) {
      return 1;
    }

    if (currentParts[part] < previousParts[part]) {
      return -1;
    }
  }

  return 0;
}

function getBumpType(current, previous) {
  const currentParts = parseVersion(current);
  const previousParts = parseVersion(previous);

  if (currentParts.major > previousParts.major) {
    return "major";
  }

  if (currentParts.minor > previousParts.minor) {
    return "minor";
  }

  if (currentParts.patch > previousParts.patch) {
    return "patch";
  }

  return "none";
}

function getBaseRef() {
  if (process.env.GITHUB_BASE_REF) {
    const baseRef = `origin/${process.env.GITHUB_BASE_REF}`;
    tryGit(["fetch", "origin", process.env.GITHUB_BASE_REF, "--depth=1"]);
    return baseRef;
  }

  if (tryGit(["rev-parse", "--verify", "HEAD^"])) {
    return "HEAD^";
  }

  return "";
}

function readPackageAt(ref) {
  if (!ref) {
    return null;
  }

  const content = tryGit(["show", `${ref}:package.json`]);

  if (!content) {
    return null;
  }

  return JSON.parse(content);
}

function getChangedFiles(baseRef) {
  if (!baseRef) {
    return [];
  }

  return git(["diff", "--name-only", baseRef, "HEAD"])
    .split("\n")
    .map((file) => file.trim())
    .filter(Boolean);
}

function normalizeForCompare(value) {
  if (Array.isArray(value)) {
    return value.map(normalizeForCompare);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nestedValue]) => [key, normalizeForCompare(nestedValue)])
    );
  }

  return value;
}

function stable(value) {
  return JSON.stringify(normalizeForCompare(value));
}

function packagePublicFieldsChanged(currentPackage, previousPackage) {
  const publicFields = ["name", "type", "main", "module", "types", "exports", "engines"];

  return publicFields.some((field) => stable(currentPackage[field]) !== stable(previousPackage[field]));
}

function isPackageContent(file) {
  return (
    file === "README.md" ||
    file === "DEPLOY.md" ||
    file === "SECURITY.md" ||
    file === "SEMVER.md" ||
    file === "package.json" ||
    file === "package-lock.json" ||
    file.startsWith("src/")
  );
}

function isPublicApiFile(file) {
  return file === "src/index.d.ts" || file === "src/index.js" || file === "src/index.cjs";
}

const currentPackage = JSON.parse(readFileSync("package.json", "utf8"));
const baseRef = getBaseRef();
const previousPackage = readPackageAt(baseRef);

if (!previousPackage) {
  console.log("No previous package.json found. Skipping SemVer guard.");
  process.exit(0);
}

const changedFiles = getChangedFiles(baseRef);
const packageContentChanged = changedFiles.some(isPackageContent);
const publicApiChanged =
  changedFiles.some(isPublicApiFile) || packagePublicFieldsChanged(currentPackage, previousPackage);

const comparison = compareVersions(currentPackage.version, previousPackage.version);
const bumpType = getBumpType(currentPackage.version, previousPackage.version);

console.log(`Previous version: ${previousPackage.version}`);
console.log(`Current version: ${currentPackage.version}`);
console.log(`Bump type: ${bumpType}`);
console.log(`Changed files: ${changedFiles.join(", ") || "(none)"}`);

if (packageContentChanged && comparison <= 0) {
  console.error("Package content changed, but package.json version did not increase.");
  process.exit(1);
}

if (publicApiChanged && bumpType === "patch") {
  console.error("Public API changed in a patch release. Use at least a minor version bump.");
  process.exit(1);
}

console.log("SemVer guard passed.");
