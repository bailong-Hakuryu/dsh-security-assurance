/** Embedded into generated modules; keep this function self-contained. */
function bridgeStrictCodecs(descriptors) {
  const bridge = codec => {
    if (codec?.mode !== 'strict' || typeof codec.typeSymbol !== 'string' || !codec.typeSymbol) {
      throw new TypeError('Security Remote requires a named strict codec')
    }
    if (codec.create !== undefined && typeof codec.create !== 'function') {
      throw new TypeError('Security Remote codec has an invalid factory')
    }
    if ('schema' in codec) {
      const schema = codec.schema
      if (typeof schema?.parse !== 'function') throw new TypeError('Security Remote codec has no parser')
      codec.create ??= () => schema
    } else {
      if (typeof codec.create !== 'function') throw new TypeError('Security Remote codec has no factory')
      const create = codec.create
      let schema
      const materialize = () => {
        if (schema === undefined) {
          const value = create.call(codec)
          if (typeof value?.parse !== 'function') throw new TypeError('Security Remote factory has no parser')
          schema = value
        }
        return schema
      }
      codec.create = materialize
      Object.defineProperty(codec, 'schema', { enumerable: true, get: materialize })
    }
  }
  for (const descriptor of descriptors) {
    for (const parameter of descriptor.parameters) bridge(parameter.codec)
    bridge(descriptor.result)
    if (descriptor.invocation.kind === 'context') bridge(descriptor.invocation.codec)
    if (descriptor.uplink !== undefined) bridge(descriptor.uplink.codec)
  }
}

/** Preserve generated validators while exposing both supported Host protocols. */
export function withCodecCompatibility(source, descriptorExpression) {
  if (!['TYPERT.invocations', 'TYPERT_REMOTE.descriptors'].includes(descriptorExpression)) {
    throw new TypeError('Unknown generated Security contribution')
  }
  return `${source}\n// Security codec compatibility (ADR 0329).\n;(${bridgeStrictCodecs.toString()})(${descriptorExpression})\n`
}
