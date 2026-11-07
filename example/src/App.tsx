import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StatusBar,
  StyleSheet,
  Switch,
  Text,
  View,
} from 'react-native';
import Security from '@rs-native-kit/security';
import type {
  DetectionResult,
  DetectionStatus,
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
  magisk: 'Magisk',
  busybox: 'BusyBox',
  jailbreak: 'Jailbreak',
  emulator: 'Emulator',
  developerMode: 'Developer mode',
  usbDebugging: 'USB debugging',
  debugger: 'Debugger',
  mockLocation: 'Mock location',
  vpn: 'VPN',
  proxy: 'Proxy',
  screenRecording: 'Screen recording',
  screenCapture: 'Screenshot',
  overlay: 'Overlay exposure',
  hooks: 'Hooking frameworks',
  frida: 'Frida',
  xposed: 'Xposed',
  lsposed: 'LSPosed',
  tampering: 'Tampering',
  signature: 'Signature',
};

const STATUS_STYLES: Record<DetectionStatus, { label: string; color: string }> =
  {
    detected: { label: 'FLAGGED', color: '#dc2626' },
    not_detected: { label: 'OK', color: '#16a34a' },
    unsupported: { label: 'N/A', color: '#6b7280' },
    not_configured: { label: 'NOT SET', color: '#d97706' },
    error: { label: 'ERROR', color: '#7c3aed' },
  };

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString();
}

function ScoreCard({ report }: { report: SecurityReport }) {
  const color = RISK_COLORS[report.riskLevel];
  return (
    <View style={[styles.scoreCard, { borderColor: color }]}>
      <Text testID="scan-score" style={[styles.scoreValue, { color }]}>
        {report.score}
      </Text>
      <Text style={styles.scoreOutOf}>/ 100</Text>
      <View style={[styles.riskBadge, { backgroundColor: color }]}>
        <Text style={styles.riskBadgeText}>{report.riskLevel} RISK</Text>
      </View>
      <Text style={styles.secureLabel}>
        {report.secure ? '✅ Device is secure' : '⚠️ Device is not secure'}
      </Text>
      <Text style={styles.platformLabel}>
        Platform: {report.platform} · Scanned {formatTime(report.timestamp)} in{' '}
        {Math.round(report.durationMs)} ms
      </Text>
      {!report.complete && (
        <Text testID="scan-incomplete" style={styles.incompleteLabel}>
          {report.failed.length} check(s) failed to run — result is incomplete
        </Text>
      )}
    </View>
  );
}

function CheckRow({
  checkKey,
  label,
  result,
}: {
  checkKey: SecurityCheckKey;
  label: string;
  result: DetectionResult;
}) {
  const { label: statusLabel, color } = STATUS_STYLES[result.status];
  return (
    <View style={styles.checkRow}>
      <View style={styles.checkText}>
        <Text style={styles.checkLabel}>{label}</Text>
        {result.status === 'detected' && (
          <Text style={styles.checkDetail}>
            {result.reasons.map(Security.describeReason).join(' · ')}
          </Text>
        )}
        {result.status === 'error' && (
          <Text style={styles.checkDetail}>{result.error}</Text>
        )}
      </View>
      <View style={[styles.checkPill, { backgroundColor: `${color}1a` }]}>
        <Text
          testID={`status-${checkKey}`}
          style={[styles.checkPillText, { color }]}
        >
          {statusLabel}
          {result.status === 'detected' ? ` · ${result.confidence}` : ''}
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
  const [protectedScreen, setProtectedScreen] = useState(false);

  const toggleProtection = useCallback((enabled: boolean) => {
    setProtectedScreen(enabled);
    Promise.all([
      Security.setScreenCaptureProtection(enabled),
      Security.setOverlayProtection(enabled),
    ]).catch((err: unknown) =>
      setError(err instanceof Error ? err.message : String(err))
    );
  }, []);

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
    <ScrollView
      style={styles.container}
      contentContainerStyle={[
        styles.content,
        { paddingTop: 16 + (StatusBar.currentHeight ?? 0) },
      ]}
      contentInsetAdjustmentBehavior="automatic"
    >
      <View style={styles.header}>
        <Text style={styles.title}>Security Dashboard</Text>
        <Pressable
          testID="refresh"
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
        <View testID="scan-error" style={styles.errorBox}>
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
                checkKey={key}
                label={CHECK_LABELS[key]}
                result={report.checks[key]}
              />
            ))}
          </View>

          {report.reasons.length > 0 && (
            <>
              <Text style={styles.sectionTitle}>Reasons</Text>
              <View style={styles.reasonsCard}>
                {report.reasons.map((reason) => (
                  <Text key={reason} style={styles.reasonText}>
                    • {Security.describeReason(reason)} ({reason})
                  </Text>
                ))}
              </View>
            </>
          )}
        </>
      )}

      <Text style={styles.sectionTitle}>Protection</Text>
      <View style={styles.protectionCard}>
        <View style={styles.checkText}>
          <Text style={styles.checkLabel}>Protect this screen</Text>
          <Text style={styles.checkDetail}>
            Blocks screenshots/recording (Android), covers the app while
            captured (iOS), and blocks overlay tapjacking (Android).
          </Text>
        </View>
        <Switch
          testID="protect-screen"
          value={protectedScreen}
          onValueChange={toggleProtection}
        />
      </View>

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
  checkText: {
    flex: 1,
    paddingRight: 12,
  },
  checkLabel: {
    color: '#374151',
  },
  checkDetail: {
    color: '#9ca3af',
    fontSize: 11,
    marginTop: 2,
  },
  incompleteLabel: {
    color: '#7c3aed',
    fontSize: 12,
    marginTop: 4,
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
  protectionCard: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    padding: 16,
    flexDirection: 'row',
    alignItems: 'center',
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
