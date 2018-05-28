"""
pdi.py - represents the Persistent Data Interface module
"""
from collections import defaultdict, namedtuple
import uuid

Block = namedtuple('Block', ['id', 'author', 'data', 'key_channel'])

class BlockNotFound(Exception):
    pass

class PDI(object):
    """
    PDI is a stand-in dummy object, which is just wrapping some lists
    that we can access by name for purposes of demonstrating the workflow.
    Note that as a dummy object it's entirely not concurrent-safe!
    """
    _channels = None

    def __init__(self):
        self._channels = defaultdict(lambda: defaultdict(list))

    def _canonicalize_path(self, channel, path):
        """ make sure we have only one way to record a path """
        channel = channel.lstrip('/')
        path = path.lstrip('/')
        return '/{}/{}'.format(channel, path)

    def write(self, author, channel, path, data, key_channel):
        """
        write a block to a channel, creating it if required.
        returns the (index, ID) of the new block for later reference.
        Note that although we use 'channel' and 'path' as params
        these are abstractions on the underlying data store. The
        key_channel is included to create the implicit ACL.
        """
        path = self._canonicalize_path(channel, path)
        _id = uuid.uuid4().hex
        block = Block(
            id=_id,
            author=author,
            data=data,
            key_channel=key_channel,
            )
        self._channels[channel][path].append(block)
        return len(self._channels[channel][path]) - 1, _id

    def read(self, channel, path, block_id=None):
        """
        return the most recent block from the given channel and path,
        optionally getting an older version of the block by passing
        its block_id.
        """
        path = self._canonicalize_path(channel, path)
        if block_id:
            for block in reversed(self._channels[channel][path]):
                if block.id == block_id:
                    return block
            raise BlockNotFound('{}: {}'.format(path, block_id))
        return self._channels[channel][path][-1]
