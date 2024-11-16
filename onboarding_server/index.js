const { Pool } = require('pg');
const { createServer } = require('http');
const axios = require('axios');

// PostgreSQL connection pool setup
const pool = new Pool({
  host: '10.0.0.17',
  user: 'postgres',
  password: 'admin',
  database: 'prisma_db',
  port: 5432,
});

// Protocol endpoints
const ENDPOINTS = {
  ICMP: '/all_icmp',
  TCP: '/all_tcp',
  UDP: '/all_udp'
};

// HTTP server setup
const server = createServer((req, res) => {
  if (req.method === 'POST') {
    const protocol = getProtocolFromUrl(req.url);
    if (protocol) {
      handleRequest(req, res, protocol);
    } else {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'Invalid endpoint' }));
    }
  } else {
    res.statusCode = 404;
    res.end();
  }
});

function getProtocolFromUrl(url) {
  if (url.includes('icmp_forwarding')) return 'ICMP';
  if (url.includes('tcp_forwarding')) return 'TCP';
  if (url.includes('udp_forwarding')) return 'UDP';
  return null;
}

async function handleRequest(req, res, protocol) {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk.toString();
  });

  req.on('end', async () => {
    try {
      const data = JSON.parse(body);
      const { dest_ip } = data;

      // Check if destination IP is registered
      const serverInfo = await findDestinationServer(dest_ip);

      if (!serverInfo.namespace_linux || !serverInfo.public_ip) {
        res.statusCode = 404;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          error: 'Destination IP not registered in database',
          details: {
            ip: dest_ip,
            timestamp: new Date().toISOString()
          }
        }));
        return;
      }

      // Forward the packet data
      const result = await forwardToTarget(
        protocol,
        serverInfo.public_ip,
        serverInfo.namespace_linux,
        data,
        req.headers['x-namespace']
      );

      res.statusCode = result.success ? 200 : 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(result));
    } catch (error) {
      console.error('Error processing request:', error.message);
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: error.message }));
    }
  });
}

// Function to find destination server information from the database
async function findDestinationServer(destIP) {
  let client = null;
  try {
    client = await pool.connect();

    // Log the input parameter to ensure it's correct
    console.log(`Looking for destIP: ${destIP} in onboarding table`);

    // Query the onboarding table to get namespace_linux and uuid_hyper
    const onboardingResult = await client.query(
      'SELECT namespace_linux, uuid_hyper FROM onboarding WHERE vm_ip = $1',
      [destIP]
    );

    if (onboardingResult.rowCount === 0) {
      console.error(`No results found for destIP: ${destIP} in onboarding table.`);
      return {
        namespace_linux: null,
        public_ip: null,
      };
    }

    const { namespace_linux, uuid_hyper } = onboardingResult.rows[0];

    // Log the values retrieved from the onboarding table
    console.log(`Found namespace_linux: ${namespace_linux}, uuid_hyper: ${uuid_hyper}`);

    // Now query the HyperV table using the uuid_hyper
    console.log(`Looking for uuid_hyperv: ${uuid_hyper} in HyperV table`);

    const hyperVResult = await client.query(
      'SELECT public_ip FROM "HyperV" WHERE uuid_hyperv = $1',
      [uuid_hyper]
    );

    if (hyperVResult.rowCount === 0) {
      console.error(`No results found for uuid_hyperv: ${uuid_hyper} in HyperV table.`);
      return {
        namespace_linux: null,
        public_ip: null,
      };
    }

    const { public_ip } = hyperVResult.rows[0];

    // Log the public_ip found
    console.log(`Found public_ip: ${public_ip}`);

    return {
      namespace_linux,
      public_ip,
    };
  } catch (error) {
    console.error('Error querying database:', error.message);
    console.error('Stack trace:', error.stack);
    throw error;
  } finally {
    if (client) {
      client.release();
    }
  }
}

async function forwardToTarget(
  protocol,
  publicIP,
  namespace,
  data,
  namespaceFromHeader
) {
  try {
    console.log(`Forwarding ${protocol} to ${publicIP}${ENDPOINTS[protocol]}`);

    const response = await axios.post(
      `http://${publicIP}${ENDPOINTS[protocol]}`,
      {
        ...data,
        namespace_linux: namespace,
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Namespace': namespaceFromHeader || namespace,
        },
      }
    );

    if (response.status === 200) {
      console.log(`${protocol} data forwarded successfully`);
      return {
        success: true,
        ...response.data
      };
    } else {
      console.error(`Error forwarding ${protocol} data:, response.data.error`);
      return {
        success: false,
        error: response.data.error,
      };
    }
  } catch (error) {
    console.error(`Error forwarding ${protocol} to target:, error.message`);
    return {
      success: false,
      error: error.message,
    };
  }
}

server.listen(8080, () => {
  console.log('Multi-protocol proxy server started on port 8080');
});
