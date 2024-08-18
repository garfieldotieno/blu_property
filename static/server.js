const jsonServer = require('json-server')
const cors = require('cors')
const server = jsonServer.create()
const router = jsonServer.router('db.json')
const middlewares = jsonServer.defaults()

// Enable CORS
server.use(cors())
server.use(middlewares)

// Custom route to transform JSON into HTML
server.get('/posts', (req, res) => {
  const posts = router.db.get('posts').value()
  const htmlPosts = posts.map(post => `
    <div class="post">
      <h2>${post.title}</h2>
      <p>${post.content}</p>
    </div>
  `).join('')
  res.send(htmlPosts)
})

// Use the default router for other endpoints
server.use(router)

// Start the server
server.listen(3000, () => {
  console.log('JSON Server is running on http://localhost:3000')
})
