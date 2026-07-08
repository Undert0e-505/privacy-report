// src/scanners/exif.ts — EXIF/metadata scanner using exiftool
import { execa } from 'execa';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import type { Finding, ScanConfig } from '../types.js';

export interface ExifScanResult {
  hasGps: boolean;
  gpsLat?: string;
  gpsLng?: string;
  deviceSerial?: string;
  ownerName?: string;
  cameraModel?: string;
  software?: string;
  timestamp?: string;
}

const IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp', '.heic', '.tiff', '.tif'];

export function isImageFile(path: string): boolean {
  const lower = path.toLowerCase();
  return IMAGE_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/** Parse exiftool JSON output. */
export function parseExifOutput(output: string): ExifScanResult {
  const result: ExifScanResult = {
    hasGps: false,
  };

  try {
    const parsed = JSON.parse(output) as Array<Record<string, unknown>>;
    if (!parsed || parsed.length === 0) return result;
    const data = parsed[0];

    // GPS
    const gpsLat = data.GPSLatitude as number | null | undefined;
    const gpsLng = data.GPSLongitude as number | null | undefined;
    if (gpsLat != null && gpsLng != null) {
      result.hasGps = true;
      result.gpsLat = String(gpsLat);
      result.gpsLng = String(gpsLng);
    }

    // Device serial
    const serial = (data.SerialNumber as string | null) ?? (data.InternalSerialNumber as string | null);
    if (serial) result.deviceSerial = String(serial);

    // Owner name
    const owner = data.OwnerName as string | undefined;
    if (owner) result.ownerName = String(owner);

    // Camera model
    const model = data.Model as string | undefined;
    if (model) result.cameraModel = String(model);

    // Software
    const software = data.Software as string | undefined;
    if (software) result.software = String(software);

    // Timestamp
    const ts = (data.DateTimeOriginal as string) ?? (data.CreateDate as string);
    if (ts) result.timestamp = String(ts);
  } catch {
    // Invalid JSON, return empty result
  }

  return result;
}

/** Scan an image buffer for EXIF metadata using exiftool. */
export async function scanImageExif(
  imageBuffer: Buffer,
  fileName: string,
): Promise<ExifScanResult> {
  // Check if exiftool is available
  try {
    await execa('exiftool', ['-ver'], { timeout: 5000 });
  } catch {
    // exiftool not available — return empty result
    return { hasGps: false };
  }

  const tempDir = join(tmpdir(), `privacy-report-exif-${randomUUID()}`);
  mkdirSync(tempDir, { recursive: true });
  const tempFile = join(tempDir, fileName);
  writeFileSync(tempFile, imageBuffer);

  try {
    const { stdout } = await execa(
      'exiftool',
      ['-n', '-json', '-GPSLatitude', '-GPSLongitude', '-SerialNumber', '-InternalSerialNumber', '-OwnerName', '-Model', '-Software', '-DateTimeOriginal', '-CreateDate', tempFile],
      { timeout: 10000 },
    );
    return parseExifOutput(stdout);
  } catch {
    return { hasGps: false };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/** Convert ExifScanResult to Finding[]. */
export function exifToFindings(
  exif: ExifScanResult,
  filePath: string,
  account: string,
  repo: string,
  config: ScanConfig,
): Finding[] {
  const findings: Finding[] = [];

  if (exif.hasGps) {
    const metadata: Record<string, string> = {};
    if (config.storeExactGps && exif.gpsLat && exif.gpsLng) {
      metadata.gpsLat = exif.gpsLat;
      metadata.gpsLng = exif.gpsLng;
    } else {
      metadata.gps = 'GPS coordinates present (redacted by default)';
    }
    if (exif.cameraModel) metadata.cameraModel = exif.cameraModel;

    findings.push({
      account,
      repo,
      file: filePath,
      rule: 'gps-metadata',
      severity: 'high',
      redactedEvidence: config.storeExactGps
        ? `GPS: ${exif.gpsLat}, ${exif.gpsLng}`
        : 'GPS metadata present (coordinates redacted)',
      metadata,
      suggestedAction: 'Strip EXIF data from images before committing.',
    });
  }

  if (exif.deviceSerial) {
    findings.push({
      account,
      repo,
      file: filePath,
      rule: 'device-serial',
      severity: 'medium',
      redactedEvidence: `Device serial: ${redactSerial(exif.deviceSerial)}`,
      suggestedAction: 'Strip EXIF data from images before committing.',
    });
  }

  if (exif.ownerName) {
    findings.push({
      account,
      repo,
      file: filePath,
      rule: 'owner-name',
      severity: 'medium',
      redactedEvidence: `Owner name: ${exif.ownerName}`,
      suggestedAction: 'Strip EXIF data from images before committing.',
    });
  }

  if (exif.cameraModel) {
    findings.push({
      account,
      repo,
      file: filePath,
      rule: 'camera-model',
      severity: 'low',
      redactedEvidence: `Camera model: ${exif.cameraModel}`,
      suggestedAction: 'Strip EXIF data from images before committing.',
    });
  }

  if (exif.software) {
    findings.push({
      account,
      repo,
      file: filePath,
      rule: 'software-metadata',
      severity: 'low',
      redactedEvidence: `Software: ${exif.software}`,
      suggestedAction: 'Strip EXIF data from images before committing.',
    });
  }

  return findings;
}

function redactSerial(serial: string): string {
  if (serial.length <= 4) return '...';
  return serial.slice(0, 2) + '...' + serial.slice(-2);
}