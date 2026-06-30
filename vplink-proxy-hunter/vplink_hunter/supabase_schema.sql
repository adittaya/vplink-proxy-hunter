CREATE TABLE IF NOT EXISTS proxy_results (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  proto TEXT DEFAULT 'http',
  latency_ms INTEGER,
  type TEXT,
  isp TEXT,
  country TEXT,
  city TEXT,
  region TEXT,
  vplink_ok BOOLEAN DEFAULT false,
  e2_ok BOOLEAN DEFAULT true,
  verified INTEGER DEFAULT 1,
  first_seen TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(ip, port)
);

CREATE INDEX IF NOT EXISTS idx_proxy_type ON proxy_results(type);
CREATE INDEX IF NOT EXISTS idx_proxy_vplink ON proxy_results(vplink_ok);
CREATE INDEX IF NOT EXISTS idx_proxy_e2 ON proxy_results(e2_ok);
CREATE INDEX IF NOT EXISTS idx_proxy_latency ON proxy_results(latency_ms);
CREATE INDEX IF NOT EXISTS idx_proxy_ip ON proxy_results(ip);

ALTER TABLE proxy_results ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "public_read" ON proxy_results;
CREATE POLICY "public_read" ON proxy_results
  FOR SELECT USING (true);

DROP POLICY IF EXISTS "service_write" ON proxy_results;
CREATE POLICY "service_write" ON proxy_results
  FOR ALL USING (auth.role() = 'service_role');
