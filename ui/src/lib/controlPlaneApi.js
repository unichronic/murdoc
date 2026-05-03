export async function getJson(path) {
    const response = await fetch(path, { credentials: 'same-origin' })
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
    return response.json()
}

export async function postJson(path, body = {}) {
    const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'same-origin',
    })
    const payload = await response.json()
    if (!response.ok) throw new Error(payload.detail || `${response.status} ${response.statusText}`)
    return payload
}

export async function putJson(path, body) {
    const response = await fetch(path, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'same-origin',
    })
    const payload = await response.json()
    if (!response.ok) throw new Error(payload.detail || `${response.status} ${response.statusText}`)
    return payload
}
