function createQueuesService({ queuesRepository }) {
  function parseQueueItemPatientId(queueItem) {
    const [idPart] = String(queueItem).split(':');
    const id = Number.parseInt(idPart.trim(), 10);
    return Number.isFinite(id) ? id : null;
  }

  function buildLastRemoved(queueItems, user) {
    return {
      queueItems,
      removedAt: new Date(),
      removedBy: user?.email || user?.username || '',
    };
  }

  function getExistingPatientIds(queueItems = []) {
    return new Set(
      queueItems
        .map(parseQueueItemPatientId)
        .filter((id) => id !== null),
    );
  }

  async function getQueueEntries() {
    const data = await queuesRepository.findQueueEntries();
    return { status: 200, body: { result: true, data } };
  }

  async function createStationQueue(stationName) {
    if (!stationName) {
      return { status: 400, body: { result: false, error: 'stationName required' } };
    }

    await queuesRepository.insertStationQueue(stationName);
    return { status: 200, body: { result: true } };
  }

  async function deleteStationQueue(stationName) {
    if (!stationName) {
      return { status: 400, body: { result: false, error: 'stationName required' } };
    }

    await queuesRepository.deleteStationQueue(stationName);
    return { status: 200, body: { result: true } };
  }

  async function addPatientsToStationQueue(stationName, queueItems) {
    if (!stationName || !Array.isArray(queueItems)) {
      return { status: 400, body: { result: false, error: 'stationName and queueItems required' } };
    }

    await queuesRepository.addQueueItems(stationName, queueItems);
    return { status: 200, body: { result: true } };
  }

  async function removePatientsFromStationQueue(stationName, queueItems, user) {
    if (!stationName || !Array.isArray(queueItems)) {
      return { status: 400, body: { result: false, error: 'stationName and queueItems required' } };
    }

    const stationQueue = await queuesRepository.findStationQueue(stationName);
    if (!stationQueue) {
      return { status: 404, body: { result: false, error: 'Station queue not found' } };
    }

    const requestedItems = new Set(queueItems);
    const removedItems = (stationQueue.queueItems || []).filter((item) => requestedItems.has(item));
    if (removedItems.length === 0) {
      return {
        status: 404,
        body: { result: false, error: 'No matching patients found in this station queue' },
      };
    }

    const updated = await queuesRepository.removeQueueItems(
      stationName,
      removedItems,
      buildLastRemoved(removedItems, user),
    );
    return { status: 200, body: { result: true, data: updated?.value || updated } };
  }

  async function removeFirstPatientFromStationQueue(stationName, user) {
    if (!stationName) {
      return { status: 400, body: { result: false, error: 'stationName required' } };
    }

    const stationQueue = await queuesRepository.findStationQueue(stationName);
    if (!stationQueue) {
      return { status: 404, body: { result: false, error: 'Station queue not found' } };
    }

    const firstItem = stationQueue.queueItems?.[0];
    if (!firstItem) {
      return { status: 404, body: { result: false, error: 'Station queue is empty' } };
    }

    const updated = await queuesRepository.updateStationQueue(stationName, {
      $pop: { queueItems: -1 },
      $set: { lastRemoved: buildLastRemoved([firstItem], user) },
    });
    return { status: 200, body: { result: true, data: updated?.value || updated } };
  }

  async function restoreLastRemovedToFront(stationName) {
    if (!stationName) {
      return { status: 400, body: { result: false, error: 'stationName required' } };
    }

    const stationQueue = await queuesRepository.findStationQueue(stationName);
    if (!stationQueue) {
      return { status: 404, body: { result: false, error: 'Station queue not found' } };
    }

    const lastRemovedItems = stationQueue.lastRemoved?.queueItems || [];
    if (lastRemovedItems.length === 0) {
      return { status: 400, body: { result: false, error: 'No recently removed patients to restore' } };
    }

    const existingIds = getExistingPatientIds(stationQueue.queueItems || []);
    const itemsToRestore = lastRemovedItems.filter((item) => {
      const id = parseQueueItemPatientId(item);
      return id !== null && !existingIds.has(id);
    });

    const update =
      itemsToRestore.length > 0
        ? {
            $push: { queueItems: { $each: itemsToRestore, $position: 0 } },
            $set: { lastRemoved: null },
          }
        : {
            $set: { lastRemoved: null },
          };

    const updated = await queuesRepository.updateStationQueue(stationName, update);

    return {
      status: 200,
      body: {
        result: true,
        data: updated?.value || updated,
        restoredCount: itemsToRestore.length,
      },
    };
  }

  async function getQueueCounters() {
    const data = await queuesRepository.findQueueCounters();
    return { status: 200, body: { result: true, data } };
  }

  async function updatePhlebotomyCounter(seq) {
    if (seq == null) {
      return { status: 400, body: { result: false, error: 'seq required' } };
    }

    await queuesRepository.updatePhlebotomyCounter(seq);
    return { status: 200, body: { result: true } };
  }

  async function getNextPatientQueueNo() {
    const result = await queuesRepository.getNextPatientQueueNo();
    const counter = result?.value || result;
    return { status: 200, body: { result: true, seq: counter.seq } };
  }

  return {
    addPatientsToStationQueue,
    createStationQueue,
    deleteStationQueue,
    getNextPatientQueueNo,
    getQueueCounters,
    getQueueEntries,
    removeFirstPatientFromStationQueue,
    removePatientsFromStationQueue,
    restoreLastRemovedToFront,
    updatePhlebotomyCounter,
  };
}

module.exports = createQueuesService;
