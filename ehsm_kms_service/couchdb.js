const nano = require('nano')

const {
  EHSM_CONFIG_COUCHDB_USERNAME,
  EHSM_CONFIG_COUCHDB_PASSWORD,
  EHSM_CONFIG_COUCHDB_SERVER,
  EHSM_CONFIG_COUCHDB_PORT,
  EHSM_CONFIG_COUCHDB_DB = 'kms_appid_info',
} = process.env

let dburl = `http://${EHSM_CONFIG_COUCHDB_USERNAME}:${EHSM_CONFIG_COUCHDB_PASSWORD}@${EHSM_CONFIG_COUCHDB_SERVER}:${EHSM_CONFIG_COUCHDB_PORT}`
dburl = 'http://admin:password@10.112.240.122:5984'
const nanoDb = nano(dburl)

async function couchDB(server) {
  try {
    await nanoDb.db.create(EHSM_CONFIG_COUCHDB_DB)
  } catch (error) {}
  const DB = await nanoDb.use(EHSM_CONFIG_COUCHDB_DB)
  server(DB)
}

module.exports = couchDB
