import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import Security from '@rs-native-kit/security';
import type {
  RiskLevel,
  SecurityCheckKey,
  SecurityEvent,
  SecurityReport,
} from '@rs-native-kit/security';

const RISK_COLORS: Record<RiskLevel, string> = {
  LOW: '#16a34a',
  MEDIUM: '#d97706',
  HIGH: '#ea580c',
  CRITICAL: '#dc2626',
};

const CHECK_LABELS: Record<SecurityCheckKey, string> = {
  root: 'Root',
  jailbreak: 'Jailbreak',
  emulator: 'Emulator',
  developerMode: 'Developer mode',
  usbDebugging: 'USB debugging',
  vpn: 'VPN',
  proxy: 'Proxy',
  overlay: 'Overlay exposure',
  frida: 'Frida',
  xposed: 'Xposed',
  lsposed: 'LSPosed',
  magisk: 'Magisk',
  busybox: 'BusyBox',
  mockLocation: 'Mock location',
  hookDetected: 'Hook detected',
  tampered: 'Tampered',
  signatureValid: 'Signature valid',
  sslPinningSupported: 'SSL pinning supported',
  screenRecording: 'Screen recording',
  screenCaptured: 'Screen captured',
  debuggerAttached: 'Debugger attached',
};

/** Checks where `true` is the *good* outcome — everything else, `true` means risk. */
const POSITIVE_CHECKS = new Set<SecurityCheckKey>([
  'signatureValid',
  'sslPinningSupported',
]);

function isCheckHealthy(key: SecurityCheckKey, value: boolean): boolean {
  return POSITIVE_CHECKS.has(key) ? value : !value;
}

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString();
}

function ScoreCard({ report }: { report: SecurityReport }) {
  const color = RISK_COLORS[report.riskLevel];
  return (
    <View style={[styles.scoreCard, { borderColor: color }]}>
      <Text style={[styles.scoreValue, { color }]}>{report.score}</Text>
      <Text style={styles.scoreOutOf}>/ 100</Text>
      <View style={[styles.riskBadge, { backgroundColor: color }]}>
        <Text style={styles.riskBadgeText}>{report.riskLevel} RISK</Text>
      </View>
      <Text style={styles.secureLabel}>
        {report.secure ? '✅ Device is secure' : '⚠️ Device is not secure'}
      </Text>
      <Text style={styles.platformLabel}>
        Platform: {report.platform} · Scanned {formatTime(report.timestamp)}
      </Text>
    </View>
  );
}

function CheckRow({ label, healthy }: { label: string; healthy: boolean }) {
  return (
    <View style={styles.checkRow}>
      <Text style={styles.checkLabel}>{label}</Text>
      <View
        style={[
          styles.checkPill,
          { backgroundColor: healthy ? '#16a34a1a' : '#dc26261a' },
        ]}
      >
        <Text
          style={[
            styles.checkPillText,
            { color: healthy ? '#16a34a' : '#dc2626' },
          ]}
        >
          {healthy ? 'OK' : 'FLAGGED'}
        </Text>
      </View>
    </View>
  );
}

function EventRow({ event }: { event: SecurityEvent }) {
  return (
    <View style={styles.eventRow}>
      <Text style={styles.eventType}>{event.type}</Text>
      <Text style={styles.eventMessage}>{event.message}</Text>
      <Text style={styles.eventTime}>{formatTime(event.timestamp)}</Text>
    </View>
  );
}

export default function App() {
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);

  const runScan = useCallback(() => {
    setLoading(true);
    setError(null);
    Security.scan()
      .then((result) => setReport(result))
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err))
      )
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    runScan();
  }, [runScan]);

  useEffect(() => {
    const unsubscribe = Security.addListener((event) => {
      setEvents((previous) => [event, ...previous].slice(0, 20));
    });
    return unsubscribe;
  }, []);

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.title}>Security Dashboard</Text>
        <Pressable
          style={({ pressed }) => [
            styles.refreshButton,
            pressed && styles.refreshButtonPressed,
          ]}
          onPress={runScan}
          disabled={loading}
        >
          <Text style={styles.refreshButtonText}>
            {loading ? 'Scanning…' : 'Refresh'}
          </Text>
        </Pressable>
      </View>

      {loading && !report && (
        <ActivityIndicator style={styles.loadingIndicator} size="large" />
      )}

      {error && (
        <View style={styles.errorBox}>
          <Text style={styles.errorTitle}>Scan unavailable</Text>
          <Text style={styles.errorMessage}>{error}</Text>
        </View>
      )}

      {report && (
        <>
          <ScoreCard report={report} />

          <Text style={styles.sectionTitle}>Checks</Text>
          <View style={styles.checksCard}>
            {(Object.keys(report.checks) as SecurityCheckKey[]).map((key) => (
              <CheckRow
                key={key}
                label={CHECK_LABELS[key]}
                healthy={isCheckHealthy(key, report.checks[key])}
              />
            ))}
          </View>

          {report.reasons.length > 0 && (
            <>
              <Text style={styles.sectionTitle}>Reasons</Text>
              <View style={styles.reasonsCard}>
                {report.reasons.map((reason, index) => (
                  <Text key={`${reason}-${index}`} style={styles.reasonText}>
                    • {reason}
                  </Text>
                ))}
              </View>
            </>
          )}
        </>
      )}

      <Text style={styles.sectionTitle}>Live security events</Text>
      <View style={styles.eventsCard}>
        {events.length === 0 ? (
          <Text style={styles.emptyEventsText}>
            No events yet — this updates in real time as VPN/proxy state
            changes, screenshots are taken, or a threat is newly detected.
          </Text>
        ) : (
          events.map((event, index) => (
            <EventRow key={`${event.timestamp}-${index}`} event={event} />
          ))
        )}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f4f5f7',
  },
  content: {
    padding: 16,
    paddingBottom: 48,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 16,
  },
  title: {
    fontSize: 22,
    fontWeight: '700',
    color: '#111827',
  },
  refreshButton: {
    backgroundColor: '#111827',
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 8,
  },
  refreshButtonPressed: {
    opacity: 0.7,
  },
  refreshButtonText: {
    color: '#ffffff',
    fontWeight: '600',
  },
  loadingIndicator: {
    marginTop: 48,
  },
  errorBox: {
    backgroundColor: '#fef2f2',
    borderColor: '#fecaca',
    borderWidth: 1,
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
  },
  errorTitle: {
    fontWeight: '700',
    color: '#991b1b',
    marginBottom: 4,
  },
  errorMessage: {
    color: '#991b1b',
  },
  scoreCard: {
    backgroundColor: '#ffffff',
    borderRadius: 16,
    borderWidth: 2,
    alignItems: 'center',
    padding: 24,
    marginBottom: 8,
  },
  scoreValue: {
    fontSize: 48,
    fontWeight: '800',
  },
  scoreOutOf: {
    color: '#6b7280',
    marginTop: -8,
    marginBottom: 8,
  },
  riskBadge: {
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 4,
    marginBottom: 8,
  },
  riskBadgeText: {
    color: '#ffffff',
    fontWeight: '700',
    fontSize: 12,
    letterSpacing: 0.5,
  },
  secureLabel: {
    fontWeight: '600',
    color: '#111827',
    marginBottom: 4,
  },
  platformLabel: {
    color: '#6b7280',
    fontSize: 12,
  },
  sectionTitle: {
    fontSize: 15,
    fontWeight: '700',
    color: '#111827',
    marginTop: 24,
    marginBottom: 8,
  },
  checksCard: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    paddingHorizontal: 16,
  },
  checkRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 12,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#e5e7eb',
  },
  checkLabel: {
    color: '#374151',
  },
  checkPill: {
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 4,
  },
  checkPillText: {
    fontSize: 11,
    fontWeight: '700',
  },
  reasonsCard: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    padding: 16,
  },
  reasonText: {
    color: '#374151',
    marginBottom: 6,
  },
  eventsCard: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    padding: 16,
    minHeight: 80,
  },
  emptyEventsText: {
    color: '#9ca3af',
  },
  eventRow: {
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#e5e7eb',
    paddingVertical: 8,
  },
  eventType: {
    fontWeight: '700',
    color: '#111827',
    fontSize: 13,
  },
  eventMessage: {
    color: '#374151',
    fontSize: 13,
  },
  eventTime: {
    color: '#9ca3af',
    fontSize: 11,
    marginTop: 2,
  },
});
