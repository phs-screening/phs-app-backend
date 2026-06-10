const MAX_PAGE_LIMIT = 100;

function createEventDashboardService({ eventDashboardRepository }) {
  function parsePagination(query = {}) {
    const page = Number.parseInt(query.page, 10);
    const requestedLimit = Number.parseInt(query.limit, 10);

    return {
      page: Number.isFinite(page) && page > 0 ? page : 1,
      limit:
        Number.isFinite(requestedLimit) && requestedLimit > 0
          ? Math.min(requestedLimit, MAX_PAGE_LIMIT)
          : 25,
    };
  }

  function buildPagination({ page, limit, total }) {
    const totalPages = Math.ceil(total / limit);

    return {
      page,
      limit,
      total,
      totalPages,
      hasNextPage: page < totalPages,
      hasPrevPage: page > 1,
    };
  }

  async function getSummary() {
    const summary = await eventDashboardRepository.getSummaryCounts();

    return {
      status: 200,
      body: {
        result: true,
        data: summary,
      },
    };
  }

  async function getIncompletePatients(query) {
    const pagination = parsePagination(query);
    const q = String(query.q ?? "").trim();
    const { data, total } =
      await eventDashboardRepository.findIncompletePatients({
        q,
        ...pagination,
      });

    return {
      status: 200,
      body: {
        result: true,
        data,
        pagination: buildPagination({ ...pagination, total }),
      },
    };
  }

  return {
    getIncompletePatients,
    getSummary,
  };
}

module.exports = createEventDashboardService;
